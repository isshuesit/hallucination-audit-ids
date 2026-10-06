"""Phase 4 behaviour, as verified against the original implementation
(see tools/verify_against_original.py). All offline - the LLM is faked."""

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hallucination_pipeline import unlearning
from hallucination_pipeline.unlearning import (
    action_for_type, build_masks, compute_effect, qualify_prompt_for,
    qualify_sentence, reconstruct_explanation,
)


class _Cfg:
    def __init__(self, **kw):
        self.kw = kw


@staticmethod
def _fake_types():
    return types.SimpleNamespace(GenerateContentConfig=_Cfg, ThinkingConfig=_Cfg)


class FakeClient:
    """Returns scripted behaviours, one per call; records every call's config."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []
        self.models = types.SimpleNamespace(generate_content=self._gen)

    def _gen(self, model=None, contents="", config=None):
        self.calls.append((contents, config))
        step = self.script.pop(0) if self.script else "default rewrite text"
        if isinstance(step, Exception):
            raise step
        return types.SimpleNamespace(text=step)


def _patch_types(monkeypatch):
    monkeypatch.setattr(unlearning, "get_types", lambda: types.SimpleNamespace(
        GenerateContentConfig=_Cfg, ThinkingConfig=_Cfg))


# ── actions ────────────────────────────────────────────────────────────────

def test_hard_hallucinations_are_removed():
    assert action_for_type("factual") == "REMOVE"
    assert action_for_type("outdated") == "REMOVE"


def test_soft_hallucinations_are_qualified():
    for t in ("reasoning", "certainty", "external_knowledge", "external_knowledge_port",
              "external_knowledge_unit", "invalid_knowledge", "overconfidence"):
        assert action_for_type(t) == "QUALIFY", t


def test_missing_or_unknown_type_is_qualified_never_removed():
    # never delete content on a guess
    assert action_for_type(None) == "QUALIFY"
    assert action_for_type("something_new") == "QUALIFY"


# ── masks ──────────────────────────────────────────────────────────────────

def _pred(sid, label, h_type, gold="__unset__"):
    p = {"alert_id": "A1", "sentence_id": sid, "predicted_label": label,
         "hallucination_type": h_type, "reason": "r"}
    if gold != "__unset__":
        p["gold_label"] = gold
    return p


def test_gold_label_overrides_the_prediction():
    masks = {m["sentence_id"]: m for m in build_masks([
        _pred("S1", "hallucinated", "factual", gold="grounded"),      # human says fine -> keep
        _pred("S2", "grounded", "reasoning", gold="hallucinated"),    # human says bad -> qualify
    ])}
    assert masks["S1"]["action"] == "KEEP"
    assert masks["S2"]["action"] == "QUALIFY"


def test_prediction_is_used_when_there_is_no_gold_label():
    masks = {m["sentence_id"]: m["action"] for m in build_masks([
        _pred("S1", "hallucinated", "factual", gold=None),
        _pred("S2", "grounded", None, gold=None),
    ])}
    assert masks == {"S1": "REMOVE", "S2": "KEEP"}


def test_hallucinated_without_a_type_becomes_external_knowledge_not_removed():
    (m,) = build_masks([_pred("S1", "hallucinated", None, gold="hallucinated")])
    assert m["hallucination_type"] == "external_knowledge"
    assert m["action"] == "QUALIFY"


# ── prompts ────────────────────────────────────────────────────────────────

def test_each_type_gets_its_own_qualify_prompt():
    reasoning = qualify_prompt_for("reasoning")
    external = qualify_prompt_for("external_knowledge")
    certainty = qualify_prompt_for("certainty")
    assert len({reasoning, external, certainty}) == 3
    assert "attack type" in reasoning
    assert "Port-to-service" in external
    assert "SOFTEN" in certainty


def test_unknown_type_defaults_to_the_reasoning_prompt():
    assert qualify_prompt_for(None) == qualify_prompt_for("reasoning")
    assert qualify_prompt_for("never_heard_of_it") == qualify_prompt_for("reasoning")


def test_protocol_subtype_uses_the_external_knowledge_prompt():
    assert qualify_prompt_for("external_knowledge_protocol") == qualify_prompt_for("external_knowledge")


# ── rewriting ──────────────────────────────────────────────────────────────

def test_rewrite_runs_with_thinking_disabled(monkeypatch):
    _patch_types(monkeypatch)
    client = FakeClient(["  Rewritten sentence.  "])
    out = qualify_sentence(client, "Original sentence here.", "reasoning", sleep=False)
    assert out == "Rewritten sentence."
    prompt, cfg = client.calls[0]
    assert prompt.endswith("Original sentence here.")
    assert cfg.kw["thinking_config"].kw["thinking_budget"] == 0


def test_rate_limiting_does_not_consume_retry_attempts(monkeypatch):
    _patch_types(monkeypatch)
    throttled = RuntimeError("429 RESOURCE_EXHAUSTED")
    client = FakeClient([throttled] * 5 + ["Finally rewritten."])  # more 429s than MAX_RETRIES
    assert qualify_sentence(client, "Some flagged sentence.", "certainty", sleep=False) == "Finally rewritten."


def test_total_failure_keeps_the_original_sentence_not_a_placeholder(monkeypatch):
    _patch_types(monkeypatch)
    client = FakeClient([RuntimeError("500 boom")] * 10)
    out = qualify_sentence(client, "The host will definitely fail soon.", "certainty", sleep=False)
    assert "host" in out and "REWRITE FAILED" not in out and "[" not in out
    assert "definitely" not in out          # certainty word was softened


def test_reconstruction_drops_removed_and_rewrites_qualified(monkeypatch):
    _patch_types(monkeypatch)
    client = FakeClient(["Rewritten third."])
    out = reconstruct_explanation(
        ["First kept sentence here.", "Second removed sentence.", "Third flagged sentence."],
        {"S1": {"action": "KEEP", "h_type": None},
         "S2": {"action": "REMOVE", "h_type": "factual"},
         "S3": {"action": "QUALIFY", "h_type": "reasoning"}},
        client,
    )
    assert out == ["First kept sentence here.", "Rewritten third."]


def test_effect_summary_numbers():
    recs = [
        {"original_sentence_count": 10, "corrected_sentence_count": 8, "sentences_removed": 3, "sentences_qualified": 2},
        {"original_sentence_count": 10, "corrected_sentence_count": 10, "sentences_removed": 0, "sentences_qualified": 0},
    ]
    e = compute_effect(recs)
    assert (e["total_sentences_before"], e["total_sentences_after"]) == (20, 18)
    assert e["avg_length_reduction_pct"] == 10.0 and e["information_retention_pct"] == 90.0
    assert e["hallucination_rate_before"] == 0.15
