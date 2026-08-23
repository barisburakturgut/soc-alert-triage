"""
Minimal MITRE ATT&CK mapping.

Findings arrive carrying technique IDs ("T1059.001 / T1027"), but triage runs on
tactics: one account walking Initial Access -> Execution -> Persistence ->
Credential Access is an intrusion, three unrelated Execution alerts are noise.

A small offline lookup covering what the upstream rule pack emits.
"""

import re

# Kill-chain order. Correlation reads spread across this list as progress.
TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Base technique ID -> tactic. Sub-techniques (T1059.001) fall back to their parent.
TECHNIQUE_TACTIC = {
    "T1566": "Initial Access",
    "T1190": "Initial Access",
    "T1078": "Initial Access",
    "T1133": "Initial Access",
    "T1189": "Initial Access",
    "T1059": "Execution",
    "T1204": "Execution",
    "T1106": "Execution",
    "T1047": "Execution",
    "T1569": "Execution",
    "T1547": "Persistence",
    "T1543": "Persistence",
    "T1053": "Persistence",
    "T1546": "Persistence",
    "T1136": "Persistence",
    "T1098": "Persistence",
    "T1505": "Persistence",
    "T1548": "Privilege Escalation",
    "T1134": "Privilege Escalation",
    "T1055": "Privilege Escalation",
    "T1027": "Defense Evasion",
    "T1140": "Defense Evasion",
    "T1562": "Defense Evasion",
    "T1218": "Defense Evasion",
    "T1070": "Defense Evasion",
    "T1112": "Defense Evasion",
    "T1036": "Defense Evasion",
    "T1197": "Defense Evasion",
    "T1220": "Defense Evasion",
    "T1003": "Credential Access",
    "T1555": "Credential Access",
    "T1110": "Credential Access",
    "T1558": "Credential Access",
    "T1552": "Credential Access",
    "T1056": "Credential Access",
    "T1040": "Credential Access",
    "T1082": "Discovery",
    "T1087": "Discovery",
    "T1018": "Discovery",
    "T1016": "Discovery",
    "T1057": "Discovery",
    "T1033": "Discovery",
    "T1012": "Discovery",
    "T1049": "Discovery",
    "T1069": "Discovery",
    "T1083": "Discovery",
    "T1135": "Discovery",
    "T1518": "Discovery",
    "T1021": "Lateral Movement",
    "T1570": "Lateral Movement",
    "T1210": "Lateral Movement",
    # Pass-the-hash is Defense Evasion too, but the analyst is chasing where the
    # stolen material got reused.
    "T1550": "Lateral Movement",
    "T1560": "Collection",
    "T1005": "Collection",
    "T1074": "Collection",
    "T1113": "Collection",
    "T1105": "Command and Control",
    "T1071": "Command and Control",
    "T1572": "Command and Control",
    "T1219": "Command and Control",
    "T1571": "Command and Control",
    "T1090": "Command and Control",
    "T1041": "Exfiltration",
    "T1048": "Exfiltration",
    "T1567": "Exfiltration",
    "T1486": "Impact",
    "T1490": "Impact",
    "T1489": "Impact",
    "T1485": "Impact",
}

_TECHNIQUE_RE = re.compile(r"T\d{4}")


def techniques(attack_field):
    """Pull the technique IDs out of a free-form ATT&CK field."""
    if not attack_field:
        return []
    seen, out = set(), []
    for tid in _TECHNIQUE_RE.findall(str(attack_field)):
        if tid not in seen:
            seen.add(tid)
            out.append(tid)
    return out


def tactics(attack_field):
    """Map an ATT&CK field to the distinct tactics it touches, in kill-chain order."""
    found = {TECHNIQUE_TACTIC[t] for t in techniques(attack_field) if t in TECHNIQUE_TACTIC}
    return sorted(found, key=lambda t: TACTIC_ORDER.index(t))


def primary_tactic(attack_field):
    """The single tactic used to select a response playbook.

    Latest in the kill chain wins: a download cradle is both Execution and
    Command and Control, and C2 is the more urgent half.
    """
    found = tactics(attack_field)
    return found[-1] if found else None


def chain_spread(attack_fields):
    """How far a set of findings walks the kill chain: (count, ordered names)."""
    found = set()
    for field in attack_fields:
        found.update(tactics(field))
    ordered = sorted(found, key=lambda t: TACTIC_ORDER.index(t))
    return len(ordered), ordered
