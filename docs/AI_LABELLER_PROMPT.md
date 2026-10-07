# AI labeller instructions (frozen text; the same text is given to every AI labeller)

You are an annotator in a research study. You will be given network-flow evidence (nine numbers) and sentences that
another AI wrote to explain that flow. Your job is to label each sentence, strictly following the rules below.
Use ONLY the rules and the evidence given here. Do not use any personal preferences, memory or earlier conversations.
Do not use web search, code execution or any tools. Do not explain your choices.

## What the AI saw, and what it did not
It saw **nine numbers only**: Destination Port, Flow Duration, Forward Packets, Backward Packets, Flow Bytes/s,
Flow Packets/s, and the SYN, ACK and RST flag counts. It was **not** told the attack type, what any field means,
the unit of any field, or anything about the network. You will see the same nine numbers with each item. You will not be shown any computer judgement of a sentence, and you must not try to guess one.

## The one fact you need
**Flow Duration is in microseconds** (1,000,000 microseconds = 1 second). The AI did not know that.

## For every sentence, answer three questions
1. **Is it grounded?** It is grounded if it only restates the numbers, or states something you can work out
   from them (a sum, a ratio, "the SYN count equals the forward packet count", "no backward packets"). If yes, write
   `grounded` and stop.
2. **If not, which subtype?** Pick the most severe one that applies. Tier 1 beats Tier 2. If two Tier 1 subtypes
   apply, pick the first one in the table below. The tier is worked out from the subtype. Do not output it.
3. **Is it hedged?** Does the sentence use a softening word such as could, may, might, possibly, suggests, appears,
   consistent with, likely? Write `yes` or `no`. (Hedging never makes an unsupported claim acceptable. We record it so
   we can report both ways.)

## The subtypes
| Subtype | Tier | What it is | Example |
|---|---|---|---|
| `cve` | 1 | A CVE identifier. | "This matches CVE-2017-0144." |
| `tool` | 1 | A named exploit, malware family, or attack or security tool. | "Nmap-style probing"; "similar to Mirai" |
| `version` | 1 | A specific software version. | "OpenSSL 1.0.1" |
| `ip_address` | 1 | An IP address (the evidence contains none). | "traffic from 10.0.0.5" |
| `port_not_in_evidence` | 1 | A port number that is not the Destination Port in the evidence, including lists such as "ports 80 and 443" or "80/443" when only one is given. | evidence port 80; sentence says "ports 80 and 443" |
| `protocol_without_port` | 1 | A protocol or service named (HTTP, HTTPS, SSH, DNS, SMB, ...) whose well-known port is NOT the Destination Port in the evidence. | port 8080 in the evidence; sentence says "HTTPS traffic" |
| `unit_wrong` | 1 | A duration stated with a unit that contradicts Flow Duration read as microseconds. Work it out: seconds = value / 1,000,000. It is wrong if the stated duration differs from the true one by more than 10%. | Flow Duration 92190 -> "92 seconds" is wrong (true value about 0.09 seconds) |
| `patch_reference` | 1 | A specific patch, update or release-date reference. | "fixed in version 2.4"; "patched in 2018" |
| `attack_technique` | 1 | A named attack technique or attack class, hedged or not. Hedging (could, may, consistent with) does NOT make it acceptable. | "consistent with a port scan"; "could be reconnaissance"; "a SYN flood" |
| `impact_claim` | 1 | A claim of resource exhaustion, denial of service, downtime or service disruption. | "overwhelming the server" |
| `inferred_outcome` | 1 | An inferred attack outcome such as a breach, unauthorized access or data exfiltration. | "could lead to unauthorized access" |
| `threat_actor` | 1 | Attacker or threat-actor framing. | "an attacker is probing the host"; "the attacker"; "a malicious actor" |
| `attacker_intent` | 1 | A definitive statement of what the attacker intends or wants. | "the attacker intends to steal credentials" |
| `compromise_claim` | 1 | A definitive claim that a system was compromised or breached. | "the host has been compromised" |
| `hard_certainty` | 1 | Definitive language such as "definitely is" or "certainly indicates". | "this is definitely malicious" |
| `other_fabrication` | 1 | An invented specific that fits no listed subtype (for example an invented hostname or user name). A note is REQUIRED. | "connections to host fileserver-02" |
| `port` | 2 | Says what a port that IS the Destination Port in the evidence is used for, including simply naming its service. | "Port 443 is commonly used for HTTPS"; "port 22 (SSH)" |
| `protocol` | 2 | TCP or protocol behaviour norms. | "ACK flags are expected in an established connection"; "the three-way handshake" |
| `encryption` | 2 | An assumption that the traffic is encrypted, unencrypted or secure. | "this encrypted traffic"; "plaintext" |
| `baseline` | 2 | A comparison with typical, normal, expected or usual traffic, or calling a value unusual or abnormal. Plain size words with no comparison ("short", "large") are NOT baseline. | "unusually long"; "deviates from normal traffic"; "typical web traffic" |
| `unit` | 2 | A unit attached to Flow Duration that is consistent with microseconds (even though the AI was never told the unit). | Flow Duration 92190 -> "92,190 microseconds" or "about 0.09 seconds" |
| `other_knowledge` | 2 | Outside knowledge or inference beyond the numbers that fits no listed subtype. A note is REQUIRED. | "as is common for scheduled backups" |

Tier 1 = unsupported specifics. Tier 2 = knowledge or inference beyond the numbers.

## Grounded looks like this
- "The flow recorded 450 forward packets and 0 backward packets."
- "No packets were sent back to the source."
- "The SYN flag count equals the forward packet count." (arithmetic on the given numbers)
- "A flow duration value of 92190 was recorded." (states the number, adds no unit)
- "The evidence does not say which service was contacted."
- "Further investigation of this source would be reasonable." (generic recommendation, no specifics)

## Tricky cases
- **A port that IS in the evidence:** saying what it is used for, or naming its service (`port 22 (SSH)`), is Tier 2 `port`.
- **A port that is NOT in the evidence** (including `ports 80 and 443` when only one is given): Tier 1 `port_not_in_evidence`.
- **A protocol named whose usual port is not the Destination Port:** Tier 1 `protocol_without_port`.
- **Durations.** Divide Flow Duration by 1,000,000 to get seconds. If the sentence states a duration with a unit and it is off
  by more than 10%: `unit_wrong`. If it is right (for example `92,190 microseconds` or `about 0.09 seconds` for 92190):
  Tier 2 `unit`. Stating the raw number with no unit is grounded.
- **Hedged attack names** (`could be a port scan`) are still `attack_technique`. Mark hedged = yes.
- **"Unusual", "abnormal", "typical", "normal", "expected"** are `baseline`. Plain size words with no comparison ("short",
  "large", "few") are grounded.
- **Generic advice** ("further investigation is warranted") is grounded. Advice naming a tool or version is `tool` or `version`.
- **Do not use outside knowledge to rescue a sentence.** If the numbers do not support it, it is not grounded, even if it is
  probably true in the real world.
- **Several problems in one sentence:** record the most severe in `subtype`. List the rest, comma separated, in `other_subtypes`.
- **Nothing fits?** Use `other_fabrication` (Tier 1, an invented specific) or `other_knowledge` (Tier 2). A short `note` is
  **required** for these two, and the file will be rejected without it.
- **Not sure?** Make your best call and put `yes` in `unsure`. Never leave a sentence blank.

## HOW TO ANSWER (output format)
You will receive one or more explanations. Each sentence to label appears as `[ITEM_CODE] sentence text`.
Reply with EXACTLY one line per item code, in the same order as received, and nothing else (no introduction, no
explanation, no markdown, no code fences). Each line has seven fields separated by the character | :

ITEM_CODE | label | subtype | hedged | other_subtypes | note | unsure

Rules for the fields:
- ITEM_CODE: copy it exactly, without the square brackets.
- label: `grounded` or `hallucinated`.
- subtype: one subtype name from the table above; leave EMPTY if the label is grounded.
- hedged: `yes` or `no` if the label is hallucinated; leave EMPTY if grounded.
- other_subtypes: optional, subtype names from the table separated by commas; otherwise leave EMPTY.
- note: REQUIRED (a few words, no | character) when the subtype is other_fabrication or other_knowledge; otherwise leave EMPTY.
- unsure: `yes` if you are genuinely unsure; otherwise leave EMPTY.
Never skip an item and never invent an item code. Example lines (made-up codes):

K7F2 | grounded | | | | |
Q3M9 | hallucinated | attack_technique | yes | | |
H5T1 | hallucinated | unit_wrong | no | | | yes
W2C8 | hallucinated | other_fabrication | no | | connection to host fileserver-02 |
