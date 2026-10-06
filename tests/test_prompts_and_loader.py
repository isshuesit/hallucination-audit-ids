import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hallucination_pipeline.data_loader import build_evidence_string, extract_evidence_tokens, sample_attack_alerts
from hallucination_pipeline.prompt_store import load_prompt

PROMPTS = ["generate_system.txt", "detect_explanation_system.txt", "detect_explanation_template.txt",
           "localize_sentence_system.txt", "qualify_reasoning.txt", "qualify_external_knowledge.txt",
           "qualify_certainty.txt", "recheck_template.txt"]


def test_every_prompt_file_loads():
    for name in PROMPTS:
        assert len(load_prompt(name)) > 100, name


def test_generation_prompt_is_verbatim_including_its_en_dash():
    # The prompt is part of the experimental protocol. An earlier hand-retyped
    # copy silently turned this en dash into a hyphen.
    assert "6\u201310 clear sentences" in load_prompt("generate_system.txt")


def test_templates_format_cleanly():
    out = load_prompt("detect_explanation_template.txt").format(evidence="E", explanation="X")
    assert "E" in out and "X" in out and "{" in out   # JSON braces survive formatting
    assert "S" in load_prompt("recheck_template.txt").format(evidence="E", sentence="S")


def test_evidence_contains_only_numbers_and_field_names():
    row = pd.Series({"Destination Port": 22, "Flow Duration": 1234, "Total Fwd Packets": 450,
                     "Total Backward Packets": 0, "Flow Bytes/s": float("inf"), "Flow Packets/s": 3.6,
                     "SYN Flag Count": 450, "ACK Flag Count": 0, "RST Flag Count": 0,
                     "Label": "SSH-Patator"})
    ev = build_evidence_string(row)
    assert "Destination Port: 22" in ev and "SYN Flag Count: 450" in ev
    assert "Flow Bytes/s" not in ev                      # infinite value is dropped, not printed
    for word in ("attack", "brute", "patator", "scan", "flood", "malicious"):
        assert word not in ev.lower()                    # the label never leaks into the evidence


def test_evidence_tokens_are_deterministic():
    assert extract_evidence_tokens("Port: 22\nPackets: 450\nRate: 3.60") == ["22", "3", "450", "60"]


def test_every_benign_spelling_is_excluded_from_attack_alerts():
    # The original loader only dropped "BENIGN", so a dataset version that calls benign
    # flows "Normal Traffic" produced 337 benign rows among 400 "attack" alerts.
    labels = ["BENIGN", "Normal Traffic", "normal traffic", " Normal Traffic ", "DoS", "DDoS", "Port Scanning"] * 20
    df = pd.DataFrame({"Label": labels})
    out = sample_attack_alerts(df, target_count=1000)
    assert set(out["Label"]) == {"DoS", "DDoS", "Port Scanning"}
