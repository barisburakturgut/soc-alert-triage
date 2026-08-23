"""
Explainable risk scoring.

Every adjustment is recorded as a contribution the report prints verbatim, so an
analyst can argue with one line of the score rather than the whole number.

    score = severity base
          + worst threat-intel verdict among the finding's indicators
          + context modifiers (off-hours, account type, external destination,
            session origin)
          + correlation modifiers (kill-chain spread, repeats, bursts)

Clamped to 0-100, then mapped to a band that carries a queue and an SLA.
"""

import re
from datetime import datetime, timedelta

_VERDICT_RANK = {
    "malicious": 4, "suspicious": 3, "unknown": 2, "clean": 1, "internal": 0, "asset": 0,
}


_MS_DATE_RE = re.compile(r"^/Date\((-?\d+)(?:[+-]\d{4})?\)/$")

_ISO_RE = re.compile(
    r"^(?P<date>\d{4}-?\d{2}-?\d{2})"
    r"(?:[T ](?P<time>\d{2}:?\d{2}(?::?\d{2})?)"
    r"(?:[.,](?P<frac>\d+))?"
    r"(?:Z|[+-]\d{2}:?\d{2}(?::?\d{2})?)?)?$"
)


def parse_time(value):
    """Parse a finding's ISO-8601 timestamp, or None if it is unusable.

    Matched by hand rather than with fromisoformat, whose grammar widened in 3.11:
    one findings file must not score differently on the 3.8 this still supports.
    Offsets are discarded, because the pipeline subtracts these and one aware
    datetime meeting a naive one aborts the batch.
    """
    if not value:
        return None
    text = str(value).strip()

    # PowerShell's ConvertTo-Json renders a DateTime as /Date(1787406739178)/,
    # Microsoft's own JSON date format. Producers on Windows emit it without
    # meaning to, and refusing it costs every finding its timestamp - which is
    # business hours, burst correlation and the case window all at once.
    epoch = _MS_DATE_RE.match(text)
    if epoch:
        try:
            return datetime(1970, 1, 1) + timedelta(milliseconds=int(epoch.group(1)))
        except (ValueError, OverflowError):
            return None

    match = _ISO_RE.match(text)
    if not match:
        return None
    date = match.group("date").replace("-", "")
    time = (match.group("time") or "000000").replace(":", "")
    time = (time + "0000")[:6]
    frac = ((match.group("frac") or "") + "000000")[:6]
    try:
        return datetime.strptime(date + time + frac, "%Y%m%d%H%M%S%f")
    except ValueError:
        return None


def account_name(user):
    """Strip the domain: 'CORP\\svc_backup' -> 'svc_backup'."""
    if not user:
        return ""
    return str(user).split("\\")[-1].split("@")[0].strip()


def classify_account(user, patterns):
    name = account_name(user).lower()
    for label in ("privileged", "service"):
        for pattern in patterns.get(label, []):
            if re.search(pattern, name, re.IGNORECASE):
                return label
    return "standard"


def worst_verdict(iocs):
    """The single indicator that drives the score, plus its verdict.

    URLs are skipped, since their host is enriched separately, and so is the
    affected asset: a host scored against its own name is circular.
    """
    ranked = [
        (i, _VERDICT_RANK.get((i.get("intel") or {}).get("verdict", "unknown"), 2))
        for i in iocs
        if i["type"] != "url"
        and i.get("role") != "asset"
        # An internal destination is reassuring; an internal source is what lateral
        # movement looks like, so it takes internal_origin instead of a discount.
        and not (i.get("role") == "source"
                 and (i.get("intel") or {}).get("verdict") == "internal")
    ]
    if not ranked:
        return None, "unknown"
    ioc, _ = max(ranked, key=lambda pair: pair[1])
    return ioc, (ioc.get("intel") or {}).get("verdict", "unknown")


def _add(contributions, label, points, reason):
    if points:
        contributions.append({"label": label, "points": int(points), "reason": reason})


def _apply(contributions, modifiers, key, label):
    """Apply one named modifier, or skip it when the hand-edited config omits it.

    A KeyError mid-batch would waste the API budget enrichment has already spent.
    """
    rule = modifiers.get(key)
    if isinstance(rule, dict):
        _add(contributions, label, rule.get("points", 0), rule.get("reason", ""))


def score_alert(alert, config, correlation=None):
    """Compute the score and the full explanation for one alert. Mutates `alert`."""
    contributions = []
    correlation = correlation or {}

    # A finding can arrive with no severity; say so rather than print "None".
    raw_severity = alert["finding"].get("Severity")
    severity = str(raw_severity).strip() if raw_severity is not None else ""
    base = (config.get("severity_base") or {}).get(severity, 10)
    _add(contributions, "Detection severity: " + (severity or "unspecified"), base,
         "starting weight assigned by the detection rule that fired" if severity else
         "the detection carried no severity, so the default starting weight applies")

    driver, verdict = worst_verdict(alert["iocs"])
    intel_rule = (config.get("intel_modifiers") or {}).get(verdict)
    if driver is not None and isinstance(intel_rule, dict):
        detail = intel_rule.get("reason", "")
        via = " (recovered only after decoding the payload)" if driver.get("via_decode") else ""
        _add(contributions, f"Threat intel: {driver['value']} ({driver.get('role', 'destination')}) = {verdict}",
             intel_rule.get("points", 0), f"{detail}{via}")
    alert["intel_verdict"] = verdict
    alert["intel_driver"] = driver

    # --- context -------------------------------------------------------------
    ctx = config.get("context_modifiers") or {}
    hours = config.get("business_hours") or {}
    when = alert["timestamp"]
    # Without all three there is no business-hours policy to compare against.
    if when is not None and {"workdays", "start_hour", "end_hour"}.issubset(hours):
        if when.weekday() not in hours["workdays"]:
            _apply(contributions, ctx, "weekend", "Context: non-working day")
        elif not (hours["start_hour"] <= when.hour < hours["end_hour"]):
            _apply(contributions, ctx, "outside_business_hours",
                   f"Context: {when.strftime('%H:%M')} is outside business hours")

    account_type = alert["account_type"]
    if account_type == "privileged":
        _apply(contributions, ctx, "privileged_account", "Context: privileged account")
    elif account_type == "service":
        _apply(contributions, ctx, "service_account", "Context: service account")

    # Gate on scope, not type: an FQDN under an internal suffix is the intranet, and
    # charging it would tax every alert that names a domain controller. Unclassified
    # scope still counts as outward-facing, because unknown reach fails safe.
    destinations = [i for i in alert["iocs"] if i.get("role") == "destination"]
    outward = [i for i in destinations
               if i["type"] in ("ip", "domain") and i.get("scope", "external") == "external"]
    if outward:
        _apply(contributions, ctx, "external_destination",
               "Context: external destination referenced")

    # The metadata endpoint is charged even where the config has no rule for it:
    # a config written before that rule existed must not quietly excuse it.
    metadata = [i for i in destinations if i.get("scope") == "link_local"]
    if metadata:
        label = f"Context: instance metadata endpoint referenced ({metadata[0]['value']})"
        fallback = ctx.get("external_destination")
        if isinstance(ctx.get("metadata_endpoint"), dict):
            _apply(contributions, ctx, "metadata_endpoint", label)
        elif isinstance(fallback, dict):
            _add(contributions, label, fallback.get("points", 0),
                 "the activity reaches the link-local instance metadata service, the "
                 "usual route from a foothold on a cloud host to that host's credentials")

    # Absent for local console activity, hence the scope check. Link-local origins
    # are unconfigured NICs and score nothing.
    origin_scope = alert.get("source_scope")
    origin = alert.get("source_ip")
    if origin_scope == "external":
        _apply(contributions, ctx, "external_origin",
               f"Context: session originated externally from {origin}")
    elif origin_scope == "internal":
        _apply(contributions, ctx, "internal_origin",
               f"Context: session originated from another internal host ({origin})")

    # --- correlation, computed across the whole batch ------------------------
    for flag in correlation.get("contributions", []):
        _add(contributions, flag["label"], flag["points"], flag["reason"])

    raw = sum(c["points"] for c in contributions)
    score = max(0, min(100, raw))

    alert["contributions"] = contributions
    alert["raw_score"] = raw
    alert["score"] = score
    alert["band"] = band_for(score, config)
    return alert


# No risk_bands configured: say so, rather than crash or invent an SLA.
_UNBANDED = {"name": "Unbanded", "min_score": 0,
             "queue": "Unassigned - no risk bands configured", "sla_minutes": None}


def _ordered_bands(config):
    """Risk bands highest-threshold first, whatever order the file lists them in.

    "First band whose min_score is met" is only correct on a descending list, and
    that file is meant to be edited. Sorting here keeps a reordered config from
    calling a 100 Informational. Ties keep file order.
    """
    bands = [b for b in (config.get("risk_bands") or []) if isinstance(b, dict)]
    return sorted(bands, key=lambda b: b.get("min_score", 0), reverse=True)


def band_for(score, config):
    bands = _ordered_bands(config)
    for band in bands:
        if score >= band.get("min_score", 0):
            return dict(band)
    return dict(bands[-1]) if bands else dict(_UNBANDED)


def band_rank(name, config):
    """Position among the bands, highest severity first. Used for thresholds."""
    names = [b.get("name") for b in _ordered_bands(config)]
    return names.index(name) if name in names else len(names)
