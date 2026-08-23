"""
The pipeline itself: findings in, triaged alerts and cases out.

    findings -> extract IOCs -> enrich -> correlate -> score -> band + playbook

Correlation runs before scoring because a batch-level fact (this account's
alerts cross five tactics) has to be available as a per-alert modifier.
"""

import inspect

from . import attack, correlate, extract, score

# extract() only scopes domains when told which suffixes are ours. Probed rather
# than hard-depended on, so an extractor without that parameter still runs.
_EXTRACT_TAKES_SUFFIXES = len(inspect.signature(extract.extract).parameters) > 1

# Band-level guidance. Recommendations only - this tool never acts on a host.
_BAND_ACTIONS = {
    "Critical": "Recommend containment now: isolate the host and disable the account pending review.",
    "High": "Recommend analyst pickup within the SLA and a decision on containment.",
    "Medium": "Recommend queued investigation with the surrounding process tree.",
    "Low": "Recommend batch review; close with a note if the context is benign.",
    "Informational": "Recommend auto-close with a note, and revisit the rule if this repeats.",
}


def _first_field(finding, names):
    for name in names:
        value = finding.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


# A finding can name several source addresses (the attacker's, and the RDP jump
# host it arrived through) and extract() sorts them by value, so "first match"
# would pick by string order. Rank by what an analyst pivots on instead. The
# bottom scopes are the ones correlate_origins refuses to group on.
_ORIGIN_SCOPE_RANK = {"external": 0, "internal": 1, "link_local": 2,
                      "loopback": 3, "reserved": 3}


def _pick_origin(iocs):
    candidates = [i for i in iocs if i.get("role") == "source" and i["type"] == "ip"]
    if not candidates:
        return None
    return min(
        candidates,
        key=lambda i: (_ORIGIN_SCOPE_RANK.get(i.get("scope"), 4), i["value"]),
    )


def playbook_for(alert, config):
    playbooks = config.get("playbooks", {})
    steps = list(playbooks.get(alert.get("primary_tactic") or "", []))
    for step in playbooks.get("_default", []):
        if step not in steps:
            steps.append(step)
    return steps


def run(findings, config, enricher):
    """Triage a list of findings. Returns (alerts, cases)."""
    alerts = []
    suffixes = config.get("internal_domain_suffixes") or []
    patterns = config.get("account_patterns") or {}
    for index, finding in enumerate(findings, start=1):
        iocs = extract.extract(finding, suffixes) if _EXTRACT_TAKES_SUFFIXES \
            else extract.extract(finding)
        for ioc in iocs:
            ioc["intel"] = enricher.enrich(ioc)

        user = finding.get("User", "")

        origin = _pick_origin(iocs)  # absent on process telemetry
        alerts.append({
            "id": f"ALRT-{index:04d}",
            "finding": finding,
            "iocs": iocs,
            "decoded": extract.decoded_commands(finding),
            "timestamp": score.parse_time(finding.get("Time")),
            "account_key": score.account_name(user).lower() or "(unknown)",
            "account_type": score.classify_account(user, patterns),
            "host": _first_field(finding, ("Host", "Hostname", "Computer", "ComputerName")),
            "source_ip": origin["value"] if origin else None,
            "source_scope": origin.get("scope") if origin else None,
            "source_verdict": (origin.get("intel") or {}).get("verdict") if origin else None,
            "logon_type": finding.get("LogonType"),
            "tactics": attack.tactics(finding.get("Attack")),
            "primary_tactic": attack.primary_tactic(finding.get("Attack")),
        })

    # Two passes because neither sees the other's shape: one user walking a kill
    # chain, one address walking many users.
    by_account = correlate.correlate(alerts, config)
    by_origin = correlate.correlate_origins(alerts, config)

    for alert in alerts:
        merged = list((by_account.get(alert["account_key"]) or {}).get("contributions", []))
        merged.extend(by_origin.get(alert["id"], []))
        score.score_alert(alert, config, {"contributions": merged})
        alert["playbook"] = playbook_for(alert, config)
        alert["recommended_action"] = _BAND_ACTIONS.get(alert["band"]["name"], "")

    alerts.sort(key=lambda a: (-a["score"], a["timestamp"] is None, a["timestamp"]))
    cases = correlate.build_cases(alerts, config)
    return alerts, cases


def to_serializable(alerts, cases, meta):
    """Flatten the result into the JSON document written to disk / posted to a webhook."""

    def alert_dict(alert):
        return {
            "id": alert["id"],
            "score": alert["score"],
            # The other renderers print "raw N clamped to M"; without this the
            # JSON reader cannot reconcile a breakdown that sums past the score.
            "raw_score": alert["raw_score"],
            "band": alert["band"]["name"],
            "queue": alert["band"]["queue"],
            "sla_minutes": alert["band"]["sla_minutes"],
            "time": alert["finding"].get("Time"),
            "user": alert["finding"].get("User"),
            "account_type": alert["account_type"],
            "host": alert["host"],
            "source_ip": alert["source_ip"],
            "source_scope": alert["source_scope"],
            "source_verdict": alert["source_verdict"],
            "logon_type": alert["logon_type"],
            "rule_id": alert["finding"].get("RuleId"),
            "rule": alert["finding"].get("Rule"),
            "severity": alert["finding"].get("Severity"),
            "attack": alert["finding"].get("Attack"),
            "tactics": alert["tactics"],
            "primary_tactic": alert["primary_tactic"],
            "command_line": alert["finding"].get("CommandLine"),
            "decoded": alert["decoded"],
            "why": alert["finding"].get("Why"),
            "intel_verdict": alert["intel_verdict"],
            "indicators": [
                {
                    "type": ioc["type"],
                    "value": ioc["value"],
                    "role": ioc.get("role", "destination"),
                    "via_decode": ioc["via_decode"],
                    "scope": ioc.get("scope"),
                    "verdict": (ioc.get("intel") or {}).get("verdict"),
                    "confidence": (ioc.get("intel") or {}).get("confidence"),
                    "provider": (ioc.get("intel") or {}).get("provider"),
                    "note": (ioc.get("intel") or {}).get("note"),
                }
                for ioc in alert["iocs"]
            ],
            "score_breakdown": alert["contributions"],
            "recommended_action": alert["recommended_action"],
            "playbook": alert["playbook"],
        }

    return {
        "meta": meta,
        "cases": [
            {
                "account": case["account"],
                "account_type": case["account_type"],
                "hosts": case["hosts"],
                "origins": case["origins"],
                "score": case["score"],
                "band": case["band"]["name"],
                "queue": case["band"]["queue"],
                "alert_count": case["alert_count"],
                "tactics": case["tactics"],
                "first_seen": case["first_seen"],
                "last_seen": case["last_seen"],
                "bad_indicators": case["bad_indicators"],
                "summary": case["summary"],
                "alert_ids": [a["id"] for a in case["alerts"]],
            }
            for case in cases
        ],
        "alerts": [alert_dict(a) for a in alerts],
    }
