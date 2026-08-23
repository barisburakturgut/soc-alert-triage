"""
Cross-alert correlation.

Seven Low findings that together describe an intrusion each get closed as a Low,
so this module scores the batch. Grouped by account, it asks:

  * do these alerts walk the ATT&CK kill chain, or sit in one tactic?
  * did the same detection fire over and over?
  * did a pile of alerts land inside a few minutes?

Regrouped by origin address it asks one more, which account-grouping cannot see:
did one address touch several accounts inside a short window? (correlate_origins)

The answers become score contributions for every alert on the account, and the
group is promoted to a case with a timeline.
"""

from . import attack
from .score import band_for


def _rule(rules, name, *required):
    """A correlation rule, or None when the config omits it or half-writes it."""
    rule = rules.get(name)
    if isinstance(rule, dict) and all(field in rule for field in required):
        return rule
    return None


def correlate(alerts, config):
    """Return {account_key: {"contributions": [...], "tactics": [...]}}."""
    rules = config.get("correlation_modifiers") or {}
    grouped = {}
    for alert in alerts:
        grouped.setdefault(alert["account_key"], []).append(alert)

    results = {}
    for account, group in grouped.items():
        contributions = []

        # --- kill-chain progression -----------------------------------------
        count, tactics = attack.chain_spread(a["finding"].get("Attack") for a in group)
        chain = _rule(rules, "kill_chain_progression",
                      "min_tactics", "points_per_tactic", "max_points")
        if chain and count >= chain["min_tactics"]:
            points = min(
                chain["max_points"],
                (count - chain["min_tactics"] + 1) * chain["points_per_tactic"],
            )
            contributions.append({
                "label": f"Correlation: {count} ATT&CK tactics on this account",
                "points": points,
                "reason": chain.get("reason", "") + " (" + " -> ".join(tactics) + ")",
            })

        # --- the same rule firing repeatedly --------------------------------
        repeat = _rule(rules, "repeat_rule", "threshold")
        if repeat:
            counts = {}
            for alert in group:
                rule_id = alert["finding"].get("RuleId", "?")
                counts[rule_id] = counts.get(rule_id, 0) + 1
            noisy = [f"{rid} x{n}" for rid, n in counts.items() if n >= repeat["threshold"]]
            if noisy:
                contributions.append({
                    "label": "Correlation: repeated detection (" + ", ".join(sorted(noisy)) + ")",
                    "points": repeat.get("points", 0),
                    "reason": repeat.get("reason", ""),
                })

        # --- alert burst -----------------------------------------------------
        burst = _rule(rules, "alert_burst", "window_minutes", "threshold")
        if burst:
            peak = _peak_in_window(group, burst["window_minutes"])
            if peak >= burst["threshold"]:
                contributions.append({
                    "label": f"Correlation: {peak} alerts within {burst['window_minutes']} minutes",
                    "points": burst.get("points", 0),
                    "reason": burst.get("reason", ""),
                })

        results[account] = {"contributions": contributions, "tactics": tactics}
    return results


def correlate_origins(alerts, config):
    """Correlate by origin address instead of by account.

    Spraying, credential stuffing and a reused stolen credential all show one
    unremarkable alert per account, and only surface once you pivot on origin.

    Returns {alert_id: [contribution, ...]} for the caller to merge in.
    """
    rule = _rule(config.get("correlation_modifiers") or {}, "shared_origin",
                 "window_minutes", "min_accounts")
    if not rule:
        return {}

    window_minutes = rule["window_minutes"]
    grouped = {}
    for alert in alerts:
        origin = alert.get("source_ip")
        # Nobody drives a session from an unconfigured NIC or the local console,
        # so grouping on one says nothing.
        if not origin or alert.get("source_scope") in ("loopback", "reserved", "link_local"):
            continue
        grouped.setdefault(origin, []).append(alert)

    results = {}
    for origin, group in grouped.items():
        for alert, accounts in _spray_windows(group, window_minutes, rule["min_accounts"]):
            names = sorted(accounts)
            results.setdefault(alert["id"], []).append({
                "label": f"Correlation: origin {origin} touched {len(names)} accounts "
                         f"within {window_minutes} minutes ({', '.join(names)})",
                "points": rule.get("points", 0),
                "reason": rule.get("reason", ""),
            })
    return results


def _spray_windows(group, window_minutes, min_accounts):
    """Yield (alert, accounts) for alerts inside a window holding enough accounts.

    The accounts come from a window that alert was actually in. Take the union
    over every qualifying window and two disjoint pairs hours apart get reported
    to all four alerts as "touched 4 accounts". Counting distinct accounts keeps
    one chatty account from satisfying the rule; on overlap, the widest wins.
    """
    timed = sorted(
        (a for a in group if a["timestamp"] is not None), key=lambda a: a["timestamp"]
    )
    span = window_minutes * 60
    flagged, start = {}, 0
    for end in range(len(timed)):
        while (timed[end]["timestamp"] - timed[start]["timestamp"]).total_seconds() > span:
            start += 1
        window = timed[start:end + 1]
        names = {a["account_key"] for a in window}
        if len(names) < min_accounts:
            continue
        for a in window:
            known = flagged.get(a["id"])
            if known is None or len(names) > len(known[1]):
                flagged[a["id"]] = (a, names)
    return list(flagged.values())


def _peak_in_window(group, window_minutes):
    """Largest number of alerts falling inside any window_minutes-wide window."""
    times = sorted(a["timestamp"] for a in group if a["timestamp"] is not None)
    if not times:
        return 0
    span = window_minutes * 60
    peak, start = 1, 0
    for end in range(len(times)):
        while (times[end] - times[start]).total_seconds() > span:
            start += 1
        peak = max(peak, end - start + 1)
    return peak


def build_cases(alerts, config):
    """Fold scored alerts into per-account cases, ranked by risk."""
    grouped = {}
    for alert in alerts:
        grouped.setdefault(alert["account_key"], []).append(alert)

    cases = []
    for account, group in grouped.items():
        group.sort(key=lambda a: (a["timestamp"] is None, a["timestamp"]))
        score = max(a["score"] for a in group)
        count, tactics = attack.chain_spread(a["finding"].get("Attack") for a in group)

        indicators = {}
        for alert in group:
            for ioc in alert["iocs"]:
                if ioc.get("role") == "asset":
                    continue
                verdict = (ioc.get("intel") or {}).get("verdict", "unknown")
                if verdict in ("malicious", "suspicious"):
                    indicators[ioc["value"]] = verdict

        hosts = []
        origins = {}
        for alert in group:
            host = alert.get("host")
            if host and host not in hosts:
                hosts.append(host)
            origin = alert.get("source_ip")
            if origin and origin not in origins:
                origins[origin] = {
                    "scope": alert.get("source_scope"),
                    "verdict": alert.get("source_verdict", "unknown"),
                }

        # Not group[0]/group[-1]: the sort parks untimed alerts at the end, which
        # would blank out a window the case really has.
        times = [a["timestamp"] for a in group if a["timestamp"]]
        first, last = (min(times), max(times)) if times else (None, None)
        cases.append({
            "account": group[0]["finding"].get("User", account),
            "account_key": account,
            "account_type": group[0]["account_type"],
            "hosts": hosts,
            "origins": origins,
            "score": score,
            "band": band_for(score, config),
            "alert_count": len(group),
            "tactics": tactics,
            "tactic_count": count,
            "bad_indicators": indicators,
            "first_seen": first.isoformat(sep=" ") if first else None,
            "last_seen": last.isoformat(sep=" ") if last else None,
            "alerts": group,
            "summary": _summarize(group, tactics, indicators, hosts, origins),
        })

    cases.sort(key=lambda c: (-c["score"], -c["alert_count"], c["account_key"]))
    return cases


def _summarize(group, tactics, indicators, hosts=(), origins=None):
    """One sentence an analyst can read instead of the whole table."""
    # .get's default only covers a missing key; "User": null is present and None.
    who = group[0]["finding"].get("User") or "an unnamed account"
    parts = [f"{len(group)} alert(s) on {who}"]
    if hosts:
        parts.append("on " + ", ".join(hosts[:3]) + (" and others" if len(hosts) > 3 else ""))
    external = [ip for ip, meta in (origins or {}).items() if meta.get("scope") == "external"]
    if external:
        parts.append("driven from outside the network via " + ", ".join(sorted(external)[:2]))
    if tactics:
        parts.append("spanning " + " -> ".join(tactics))
    bad = [value for value, verdict in indicators.items() if verdict == "malicious"]
    if bad:
        parts.append("touching known-bad " + ", ".join(sorted(bad)[:3]))
    return ", ".join(parts) + "."
