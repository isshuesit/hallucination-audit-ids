"""
Rule-based hallucination classifiers.

Two entry points:
  rule_classify_sentence()        - sentence-level (used by localization)
  rule_based_detect_explanation() - explanation-level (used by detection)

Both apply the same four rule layers in the same order:
  1. Hard patterns (factual / reasoning / certainty)
  2. Port-number mismatch (a port is named that isn't in the evidence)
  3. Protocol injection (a protocol is named whose expected port is absent)
  4. External knowledge (port meaning, TCP norms, encryption, unit conversion)
Then falls back to "ambiguous" (sentence-level) or "medium confidence,
escalate" (explanation-level) if only soft certainty language is present.

This logic is unchanged from what produced the paper's reported numbers -
only the massive duplicated dead-code wrapper around it was removed.
"""

from __future__ import annotations

import re

from .patterns import (
    ALL_RULE_PATTERNS,
    EXTERNAL_KNOWLEDGE_PATTERNS,
    PROTOCOL_NAME_RE,
    SOFT_CERTAINTY_RE,
    TYPE_PRIORITY,
    protocol_to_ports,
)


def check_protocol_injection(text: str, evidence_tokens: set[str]) -> list[dict]:
    """Flag protocol names whose well-known port is absent from the evidence.
    Port 443 in evidence + 'HTTPS' in text = fine. 'TLS' in text with no 443
    in evidence = the model inferred a service the evidence never showed.
    """
    proto_to_ports = protocol_to_ports()
    violations: list[dict] = []
    seen: set[str] = set()

    for proto in PROTOCOL_NAME_RE.findall(text):
        proto_lower = proto.lower()
        if proto_lower in seen:
            continue
        seen.add(proto_lower)

        allowed_ports = proto_to_ports.get(proto_lower, [])
        if not allowed_ports:
            violations.append({
                "rule": f"Protocol '{proto}' has no well-known port",
                "type": "factual", "matched": [proto],
            })
        elif not any(p in evidence_tokens for p in allowed_ports):
            violations.append({
                "rule": f"Protocol '{proto}' named but port {allowed_ports} not in evidence",
                "type": "factual", "matched": [proto],
            })
    return violations


def check_external_knowledge(text: str) -> list[dict]:
    """Return external-knowledge violations found in *text*."""
    violations: list[dict] = []
    seen: set[str] = set()

    for pattern, description in EXTERNAL_KNOWLEDGE_PATTERNS:
        matches = pattern.findall(text)
        if not matches:
            continue
        match_strs = [m if isinstance(m, str) else m[0] for m in matches]
        novel = [m for m in match_strs if m.lower().strip() not in seen]
        if novel:
            seen.update(m.lower().strip() for m in novel)
            violations.append({
                "rule": description, "type": "external_knowledge", "matched": novel[:3],
            })
    return violations


def rule_classify_sentence(sentence: str, evidence_tokens: set[str]) -> dict:
    """Apply all four rule layers to a single sentence.
    Returns label in {"hallucinated", "grounded", "ambiguous"}.
    """
    for pattern, h_type, description in ALL_RULE_PATTERNS:
        raw_matches = pattern.findall(sentence)
        if not raw_matches:
            continue
        match_strs = [m if isinstance(m, str) else m[0] for m in raw_matches]
        novel = [m for m in match_strs if m.lower().strip() not in evidence_tokens]
        if novel:
            return {
                "label": "hallucinated", "confidence": "high",
                "hallucination_type": h_type,
                "reason": f"{description}: {novel[:2]}",
                "detection_method": "rule_pattern", "matched": novel[:3],
            }

    novel_ports = [
        p for p in re.findall(r"\bport\s+(\d+)\b", sentence, re.IGNORECASE)
        if p not in evidence_tokens
    ]
    if novel_ports:
        return {
            "label": "hallucinated", "confidence": "high",
            "hallucination_type": "factual",
            "reason": f"Port(s) {novel_ports} not in evidence",
            "detection_method": "rule_port_mismatch",
            "matched": [f"port {p}" for p in novel_ports],
        }

    proto_violations = check_protocol_injection(sentence, evidence_tokens)
    if proto_violations:
        return {
            "label": "hallucinated", "confidence": "high",
            "hallucination_type": proto_violations[0]["type"],
            "reason": proto_violations[0]["rule"],
            "detection_method": "rule_protocol_injection",
            "matched": proto_violations[0]["matched"],
        }

    ext_violations = check_external_knowledge(sentence)
    if ext_violations:
        v = ext_violations[0]
        return {
            "label": "hallucinated", "confidence": "high",
            "hallucination_type": "external_knowledge",
            "reason": f"{v['rule']}: {v['matched'][:2]}",
            "detection_method": "rule_external_knowledge",
            "matched": v["matched"],
        }

    soft_hits = SOFT_CERTAINTY_RE.findall(sentence)
    if soft_hits:
        return {
            "label": "ambiguous", "confidence": "medium",
            "hallucination_type": "certainty",
            "reason": f"Soft certainty markers: {soft_hits[:3]}",
            "detection_method": "rule_soft_certainty", "matched": soft_hits,
        }

    return {
        "label": "grounded", "confidence": "high",
        "hallucination_type": None,
        "reason": "Passed all rule layers. No unsupported claims detected.",
        "detection_method": "rule_clean", "matched": [],
    }


def rule_based_detect_explanation(explanation: str, evidence_tokens: list | set) -> dict:
    """Explanation-level (not sentence-level) hallucination detection.
    Returns triggered in {True, False, None} where None means 'medium
    confidence, escalate to LLM judge'.
    """
    evidence_token_set = {str(t).lower() for t in evidence_tokens}
    matched_rules: list[dict] = []

    for pattern, h_type, description in ALL_RULE_PATTERNS:
        raw_matches = pattern.findall(explanation)
        if not raw_matches:
            continue
        match_strs = [m if isinstance(m, str) else m[0] for m in raw_matches]
        novel = [m for m in match_strs if m.lower() not in evidence_token_set]
        if novel:
            matched_rules.append({"rule": description, "type": h_type, "matched": novel[:3]})

    for port in re.findall(r"\bport\s+(\d+)\b", explanation, re.IGNORECASE):
        if port not in evidence_token_set:
            matched_rules.append({
                "rule": f"Port {port} mentioned but not in evidence",
                "type": "factual", "matched": [f"port {port}"],
            })

    matched_rules.extend(check_protocol_injection(explanation, evidence_token_set))
    soft_hits = SOFT_CERTAINTY_RE.findall(explanation)

    if matched_rules:
        matched_rules.sort(key=lambda r: TYPE_PRIORITY.get(r["type"], 99))
        return {
            "triggered": True, "confidence": "high",
            "matched_rules": matched_rules,
            "hallucination_type": matched_rules[0]["type"],
            "reason": "; ".join(r["rule"] for r in matched_rules[:2]),
        }
    if soft_hits:
        return {
            "triggered": None, "confidence": "medium", "matched_rules": [],
            "hallucination_type": "certainty",
            "reason": f"Soft certainty markers: {soft_hits[:3]}",
        }
    return {
        "triggered": False, "confidence": "high", "matched_rules": [],
        "hallucination_type": None, "reason": "No rule patterns matched.",
    }
