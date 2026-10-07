# Known rule gaps

The rule patterns are frozen (RULES_VERSION 1.0.0, patterns SHA-256 `1d10799f...`). These are claims that
`docs/ANNOTATION_GUIDE_v2.md` and the v2 judge prompts treat as hallucinations but the rules do not catch. They are
**not fixed**: changing a rule would change the C0 reproduction of the old run and needs a `RULES_VERSION` bump and a
DECISIONS entry. They are listed so that rule-only numbers can be read correctly: these misses lower rule recall
against the human labels, and the LLM judge (C2/C3) is expected to catch them.

Each gap has a test in `tests/test_known_rule_gaps.py` that asserts the current rules MISS it, at sentence level
(`policy.classify_sentence_rules`) and at explanation level (with the Tier 2 layer on). If a rule change ever
catches one, that test fails as a reminder to update this file.

| # | Example (evidence) | What the guide says | Why the rules miss it |
|---|---|---|---|
| G1 | "Traffic used ports 80 and 443 during this flow." (port 80 only) | Tier 1 `port_not_in_evidence` | The port-mismatch rule only matches `port <number>`; a second number after "ports 80 and" is never read as a port. |
| G2 | "Traffic went to port 80/443 during this flow." (port 80 only) | Tier 1 `port_not_in_evidence` | `port\s+(\d+)` takes only the first number (80, which is in the evidence); "/443" is ignored. |
| G3 | "The attacker is probing this host repeatedly." | Tier 1 `threat_actor` | The threat-actor pattern lists "an attacker", not "the attacker"; the certainty pattern for "the attacker" needs intends/plans/wants/aims/is trying/will. ("An attacker is probing..." IS caught.) |
| G4 | "Port 22, which is SSH, was the destination." (port 22) | Tier 2 `port` | The protocol rule only flags a protocol whose port is ABSENT; naming the service of a PRESENT port matches no port-characterisation phrase ("commonly used for", "standard port for", ...). |

Reported by the paper side, 2026-10-07. Add new gaps here with a test; never fix them silently.
