"""
Rule-based hallucination pattern definitions.

This is the ONE copy of these patterns. The original project had this exact
same content duplicated three times across ~2,000 lines (two dead commented-out
copies followed by one live copy) - this file is the live copy, cleaned up,
with nothing else changed. The regex logic itself is unmodified from what
produced the results reported in the paper; only the surrounding clutter
was removed.
"""

from __future__ import annotations

import re

# ── Well-known port <-> protocol whitelist ──────────────────────────────────
# Used to check: if the explanation names a protocol (e.g. "HTTPS"), is the
# corresponding port actually present in the evidence? If not, that's a
# hallucination - the model inferred a service the evidence never showed.
WELLKNOWN_PORT_PROTOCOLS: dict[str, list[str]] = {
    "21": ["ftp"],
    "22": ["ssh"],
    "23": ["telnet"],
    "25": ["smtp"],
    "53": ["dns", "domain name system"],
    "80": ["http"],
    "110": ["pop3"],
    "143": ["imap"],
    "443": ["https", "tls", "ssl"],
    "445": ["smb"],
    "3306": ["mysql"],
    "3389": ["rdp"],
    "5432": ["postgresql"],
    "3050": ["firebird"],
}

_PROTO_TO_PORTS: dict[str, list[str]] = {}
for _port, _protos in WELLKNOWN_PORT_PROTOCOLS.items():
    for _proto in _protos:
        _PROTO_TO_PORTS.setdefault(_proto.lower(), []).append(_port)

PROTOCOL_NAME_RE = re.compile(
    r"\b(https?|ssh|ftp|smtp|dns|tls|ssl|rdp|smb|imap|pop3|"
    r"telnet|ldap|snmp|mysql|postgresql|firebird|domain name system)\b",
    re.IGNORECASE,
)

# ── Factual hallucinations: things that must be named explicitly ───────────
FACTUAL_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE),
     "factual", "CVE identifier not present in evidence"),
    (re.compile(
        r"\b(metasploit|eternalblue|eternal blue|meterpreter|mimikatz|"
        r"cobalt strike|nmap|masscan|hydra|medusa|john the ripper|"
        r"hashcat|sqlmap|burp suite|wireshark|snort|suricata|"
        r"heartbleed|shellshock|wannacry|notpetya|mirai|zeus|"
        r"emotet|trickbot|ransomware)\b", re.IGNORECASE),
     "factual", "Named exploit or attack tool"),
    (re.compile(
        r"\bv\d+\.\d+|\bversion\s+\d+|\bopenssl\s+\d|\bapache\s+\d",
        re.IGNORECASE),
     "factual", "Specific software version"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
     "factual", "IP address stated — not in evidence"),
    (re.compile(
        r"\b(patch\s+(?:MS|KB)\d+|update\s+to\s+version|"
        r"fixed in\s+version|released in\s+\d{4})\b", re.IGNORECASE),
     "outdated", "Specific patch or version reference"),
]

# ── Reasoning hallucinations: attack-mechanism claims beyond the evidence ──
REASONING_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(
        r"\b(dns.tunnel(?:ing|ed)?|dns exfiltration|"
        r"data exfiltration|exfiltrat(?:e|ion|ing)|"
        r"command.and.control|c2 (?:server|traffic|beacon|channel)|"
        r"lateral movement|privilege escalation|"
        r"syn flood|udp flood|icmp flood|http flood|"
        r"amplification attack|reflection attack|"
        r"brute.forc(?:e|ing)|credential (?:stuffing|spray)|"
        r"password spray|dictionary attack|"
        r"malware|botnet|trojan|backdoor|rootkit|"
        r"port scan(?:ning)?|network scan(?:ning)?|"
        r"reconnaissance|host discovery|banner grabbing|"
        r"zero.day|exploit(?:ing|ation)?|vulnerability)\b", re.IGNORECASE),
     "reasoning", "Named attack technique — not derivable from flow numbers"),
    (re.compile(
        r"\b(resource exhaustion|bandwidth exhaustion|"
        r"connection.pool|thread.pool|memory exhaustion|cpu exhaustion|"
        r"overwhelm(?:ing|ed)?\s+the\s+(?:server|target|host|network)|"
        r"flood(?:ing)?\s+the|saturate the bandwidth|"
        r"denial.of.service|service disruption|downtime)\b", re.IGNORECASE),
     "reasoning", "Resource exhaustion / DoS impact claim"),
    (re.compile(
        r"\b(?:could|may|might|will|would)\s+"
        r"(?:result in|lead to|cause|allow|enable|facilitate)\s+"
        r"(?:unauthorized|a breach|data exfiltration|lateral movement|"
        r"privilege escalation|remote (?:access|code execution)|"
        r"system compromise|downtime)\b", re.IGNORECASE),
     "reasoning", "Inferred attack outcome"),
    (re.compile(
        r"\b(an attacker|a malicious actor|threat actor|"
        r"adversary|the adversary|a malicious user|"
        r"a bad actor|a threat agent)\b", re.IGNORECASE),
     "reasoning", "Threat-actor framing — not supportable from flow features"),
]

# ── Certainty hallucinations: overconfident language ────────────────────────
CERTAINTY_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(
        r"\b(the attacker (?:intends?|plans?|wants?|aims?|is trying|will)\b)",
        re.IGNORECASE),
     "certainty", "Definitive attacker intent"),
    (re.compile(
        r"\b(the (?:server|system|host|machine|network) (?:has been|was|is) "
        r"(?:compromised|breached|infected|pwned|hacked))\b", re.IGNORECASE),
     "certainty", "Definitive compromise claim"),
    (re.compile(
        r"\b(?:definitely|certainly|undoubtedly|absolutely)\s+"
        r"(?:will|is|has|compromised|infected|indicates)\b", re.IGNORECASE),
     "certainty", "Hard certainty language"),
]

SOFT_CERTAINTY_RE = re.compile(
    r"\b(always indicates?|is always|must be|is definitely|"
    r"will inevitably|cannot be anything other|definitely|certainly|"
    r"without doubt|absolutely will|guaranteed to)\b", re.IGNORECASE,
)

ALL_RULE_PATTERNS: list[tuple[re.Pattern, str, str]] = (
    FACTUAL_PATTERNS + REASONING_PATTERNS + CERTAINTY_PATTERNS
)

TYPE_PRIORITY = {
    "factual": 0, "certainty": 1, "reasoning": 2,
    "external_knowledge": 3, "outdated": 4,
}

# ── External knowledge: true but not derivable from raw numbers alone ──────
EXTERNAL_KNOWLEDGE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(
        r"\b("
        r"commonly\s+(?:used|associated|utilized)\s+(?:for|with)|"
        r"conventionally\s+(?:used|utilized|associated)\s+(?:for|with)|"
        r"primarily\s+associated\s+with|"
        r"standard\s+port\s+for|"
        r"typically\s+(?:used|associated)\s+(?:for|with)|"
        r"well.known\s+port\s+for|"
        r"is\s+the\s+(?:default|standard|common|well.known)\s+port|"
        r"designated\s+for|reserved\s+for|"
        r"used\s+for\s+(?:HTTPS?|SSH|FTP|SMTP|DNS|RDP|SMB|NTP|IMAP|POP3|Telnet)|"
        r"not\s+typically\s+associated\s+with\s+standard"
        r")\b", re.IGNORECASE),
     "Port characterization — labelling a port's purpose is external knowledge"),
    (re.compile(
        r"\b("
        r"typical(?:ly)?\s+(?:TCP|HTTPS?|web|established|network)\b|"
        r"normal\s+(?:TCP|HTTPS?|web|network|traffic|behavior|communication)\b|"
        r"expected\s+(?:TCP|HTTPS?|web|behavior|traffic)\b|"
        r"(?:for\s+a\s+|in\s+a\s+)(?:typical|normal|properly\s+functioning|"
        r"standard|established|fully\s+established)\s+(?:TCP|HTTP|HTTPS|web|"
        r"connection|session|communication)\b|"
        r"ACK\s+flags?\s+(?:are|is|would\s+be)\s+(?:essential|expected|required|"
        r"typical|necessary|normal)\b|"
        r"three.way\s+handshake\b|"
        r"fully\s+established\s+(?:TCP\s+)?(?:connection|session)\b"
        r")", re.IGNORECASE),
     "Protocol behavior knowledge — TCP/HTTP session norms are external knowledge"),
    (re.compile(
        r"\b(encrypt(?:ed|ion)|unencrypt(?:ed|ion)|"
        r"secure\s+web\s+traffic|"
        r"secure\s+(?:communication|connection|channel|session|transfer)\b|"
        r"SSL[/ ]TLS|"
        r"plaintext\s+(?:traffic|communication|data)\b)\b", re.IGNORECASE),
     "Encryption assumption — not in flow evidence"),
    (re.compile(
        r"\b("
        r"typical\s+web\s+traffic|"
        r"standard\s+web\s+(?:traffic|browsing|behavior)\b|"
        r"normal\s+(?:browsing|web|network)\s+(?:pattern|behavior|activity)\b|"
        r"deviates?\s+(?:significantly\s+)?from\s+(?:typical|normal|standard|expected)\b|"
        r"highly\s+anomalous\s+(?:behavior\s+)?for\b|"
        r"unusual\s+for\s+(?:a\s+)?(?:typical|normal|standard\s+)?(?:TCP|HTTPS?|web|established)\b|"
        r"not\s+(?:typical|normal|characteristic)\s+(?:of|for)\s+(?:legitimate|normal|standard|typical|regular)\b"
        r")", re.IGNORECASE),
     "External baseline comparison — requires outside knowledge"),
    (re.compile(
        r"\b(?:"
        r"(?:lasted?|persisted?|flow\s+lasted?)\s+for\s+(?:only\s+|approximately\s+|about\s+)?"
        r"(?:\d+(?:\.\d+)?\s+)?(?:hours?|minutes?|seconds?)\b|"
        r"(?:lasted?|persisted?|lasted\s+approximately|persisted?\s+for|duration\s+of)\s+"
        r"(?:approximately\s+)?(?:\d+(?:\.\d+)?\s+)?(?:hours?|minutes?|seconds?)\b|"
        r"approximately\s+\d+(?:\.\d+)?\s+(?:hours?|minutes?|seconds?)\b|"
        r"(?:over|about|around|nearly|almost|more\s+than)\s+\d+(?:\.\d+)?\s+(?:hours?|minutes?)\b|"
        r"lasting\s+(?:only\s+|approximately\s+)?\d+.*?(?:hours?|minutes?|seconds?)\b"
        r")", re.IGNORECASE),
     "Unit assumption — raw flow duration has no guaranteed unit"),
]

_SENT_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def split_sentences(text: str, min_len: int = 15) -> list[str]:
    """Split text on sentence boundaries, drop very short fragments."""
    return [s.strip() for s in _SENT_SPLIT_RE.split(text.strip())
            if len(s.strip()) >= min_len]


def protocol_to_ports() -> dict[str, list[str]]:
    """Expose the reverse protocol->ports map for use by rules.py."""
    return _PROTO_TO_PORTS
