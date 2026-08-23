"""
Reporting: a triage queue, not a findings table.

An analyst picks up a case and works it, so both renderers nest alerts inside
their case and neither ever emits a flat list. The HTML is one self-contained
file with no external assets, so it can be attached to a ticket.
"""

import html
import os
import re
import sys

BAND_COLORS = {
    "Critical": "\033[97;41m",
    "High": "\033[91m",
    "Medium": "\033[93m",
    "Low": "\033[96m",
    "Informational": "\033[90m",
}
BAND_HTML = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}
BAND_HEX = {
    "Critical": "#c62828",
    "High": "#e05d1f",
    "Medium": "#b8860b",
    "Low": "#2f6f9f",
    "Informational": "#6b7280",
}
RESET = "\033[0m"
DIM = "\033[90m"
BOLD = "\033[1m"

_COLOR_ENABLED = True

# Findings carry attacker-chosen text, so printing it raw could repaint the
# screen with a forged verdict. Tab survives, newline does not (a finding would
# forge its own report lines), and bidi goes because a filename carrying U+202E
# renders as a .png while it is still an executable on disk.
_CONTROL = re.compile(
    "[\\x00-\\x08\\x0a-\\x1f\\x7f-\\x9f\\u00ad\\u061c\\u180e"
    "\\u200b-\\u200f\\u202a-\\u202e\\u2028\\u2029\\u2066-\\u2069\\ufeff]"
)

# The document has to stay attachable: uncapped, 5,000 findings render as a 22 MB
# file most trackers refuse. Every cap announces itself and points at the JSON.
MAX_CASES = 100
MAX_ALERTS_PER_CASE = 25
MAX_IOC_ROWS = 25
MAX_COMMAND_CHARS = 2000


def enable_color(enabled=True):
    """Prepare the console: ANSI handling (Windows asks) and a tolerant encoder."""
    global _COLOR_ENABLED
    # Redirected stdout falls back to the ANSI codepage, where a Turkish or CJK
    # hostname would abort the run before any report file is written.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass

    _COLOR_ENABLED = enabled and sys.stdout.isatty()
    if _COLOR_ENABLED and os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            _COLOR_ENABLED = False


def _c(text, color):
    return f"{color}{text}{RESET}" if _COLOR_ENABLED else str(text)


def _s(value):
    """A JSON null in a finding field still has to print as an empty string."""
    return "" if value is None else str(value)


def neutralise(value):
    """Strip escapes and bidi from attacker-chosen text; the webhooks need it too."""
    return _CONTROL.sub("", _s(value))


def _safe(value):
    return neutralise(value)


def _h(value):
    """Neutralise, then escape - html.escape does neither control nor bidi."""
    return html.escape(_safe(value))


def _account(case):
    """Falls back through account_key, since a finding may carry User: null."""
    return (_safe(case.get("account")) or _safe(case.get("account_key"))
            or "unknown account")


def _sla(band):
    minutes = band.get("sla_minutes")
    if not minutes:
        return "no SLA"
    return f"{minutes} min" if minutes < 60 else f"{minutes // 60} h"


# --------------------------------------------------------------------------
# console
# --------------------------------------------------------------------------

def print_console(alerts, cases, meta, show_breakdown=True):
    width = 78
    rule = "=" * width

    print()
    print(_c(rule, DIM))
    print(_c("  ALERT TRIAGE QUEUE", BOLD) + _c(f"   engine v{meta['version']}", DIM))
    print(_c("  Intake     : ", DIM) + f"{meta['input']}  ({meta['finding_count']} finding(s))")
    print(_c("  Enrichment : ", DIM) + meta["enrichment"])
    print(_c("  Indicators : ", DIM) + f"{meta['lookups']} looked up, {meta['cache_hits']} from cache")
    print(_c(rule, DIM))

    counts = {}
    for alert in alerts:
        counts[alert["band"]["name"]] = counts.get(alert["band"]["name"], 0) + 1
    print("  " + "   ".join(
        _c(f"{name}: {counts.get(name, 0)}", BAND_COLORS.get(name, ""))
        for name in ("Critical", "High", "Medium", "Low", "Informational")
    ))
    print(_c(f"  {len(alerts)} alert(s) folded into {len(cases)} case(s).", DIM))

    for position, case in enumerate(cases, start=1):
        _print_case(position, case, show_breakdown)

    print()
    print(_c(rule, DIM))
    print(_c("  Recommendations only - this tool never changes or contains anything.", DIM))
    print(_c(rule, DIM))
    print()


def _print_case(position, case, show_breakdown):
    name = case["band"]["name"]
    color = BAND_COLORS.get(name, "")

    print()
    print(_c("-" * 78, DIM))
    print(_c(f"  CASE #{position}  [{case['score']:>3}/100] {name.upper()}", color)
          + f"   {_account(case)}")
    print(_c(f"    queue: {_safe(case['band']['queue'])}   SLA: {_sla(case['band'])}"
             f"   account: {_safe(case['account_type'])}   alerts: {case['alert_count']}", DIM))
    print(f"    {_safe(case['summary'])}")
    if case.get("hosts"):
        print(_c("    hosts:  ", DIM) + ", ".join(_safe(h) for h in case["hosts"]))
    for origin, meta in sorted((case.get("origins") or {}).items()):
        scope = _safe(meta.get("scope")) or "?"
        verdict = _safe(meta.get("verdict")) or "unknown"
        label = {"external": "EXTERNAL", "internal": "internal"}.get(scope, scope)
        print(_c("    origin: ", DIM) + f"{_safe(origin)}  [{label}, intel: {verdict}]")
    if case["tactics"]:
        print(_c("    chain:  ", DIM) + " -> ".join(_safe(t) for t in case["tactics"]))
    if case["bad_indicators"]:
        for value, verdict in sorted(case["bad_indicators"].items()):
            print(_c("    ioc:    ", DIM) + f"{_safe(value)}  [{_safe(verdict)}]")
    print(_c(f"    window: {_safe(case['first_seen']) or '?'}  ..  "
             f"{_safe(case['last_seen']) or '?'}", DIM))
    print()

    for alert in case["alerts"]:
        _print_alert(alert, show_breakdown)


def _print_alert(alert, show_breakdown):
    finding = alert["finding"]
    name = alert["band"]["name"]

    # "Informational" is 13 characters; a narrower field runs the band name
    # straight into the rule it labels.
    print(_c(f"    {alert['id']}  [{alert['score']:>3}] {name:<15}", BAND_COLORS.get(name, ""))
          + _safe(finding.get("Rule")))
    print(_c(f"      {_safe(finding.get('Time')) or '?'}   {_safe(finding.get('Attack'))}   "
             f"log: {_safe(finding.get('Source'))}", DIM))

    if alert.get("host"):
        print(_c("      host:    ", DIM) + _safe(alert["host"]))
    if alert.get("source_ip"):
        scope = _safe(alert.get("source_scope")) or "?"
        logon = f", logon type {_safe(alert['logon_type'])}" if alert.get("logon_type") else ""
        print(_c("      from:    ", DIM) + f"{_safe(alert['source_ip'])}  ({scope}{logon})")

    command = _safe(finding.get("CommandLine")).strip()
    if command:
        print(_c("      cmd:     ", DIM) + _truncate(command, 60))
    for decoded in alert["decoded"]:
        print(_c("      decoded: ", DIM) + _c(_truncate(decoded, 60), "\033[95m" if _COLOR_ENABLED else ""))

    for ioc in alert["iocs"][:MAX_IOC_ROWS]:
        verdict = (ioc.get("intel") or {}).get("verdict") or "unknown"
        mark = {"malicious": "!!", "suspicious": " !", "clean": " .",
                "internal": " -", "asset": " =", "unknown": " ?"}.get(verdict, " ?")
        tag = "  (via decode)" if ioc["via_decode"] else ""
        role = _safe(ioc.get("role") or "destination")
        print(f"      {mark} {role:<11} {_safe(ioc['type']):<7} {_safe(ioc['value'])}"
              f"  -> {_safe(verdict)}{tag}")
    # One alert carrying a few hundred addresses would otherwise bury the queue.
    extra = len(alert["iocs"]) - MAX_IOC_ROWS
    if extra > 0:
        print(_c(f"       + {extra} more indicator(s) - see the JSON export", DIM))

    if show_breakdown:
        print(_c("      why this score:", DIM))
        for item in alert["contributions"]:
            sign = "+" if item["points"] >= 0 else ""
            print(f"        {sign}{item['points']:>3}  {_safe(item['label'])}")
            print(_c(f"              {_safe(item['reason'])}", DIM))
        if alert["raw_score"] != alert["score"]:
            print(_c(f"        (raw {alert['raw_score']} clamped to {alert['score']})", DIM))

    print(_c("      action:  ", DIM) + _safe(alert["recommended_action"]))
    print()


def _clip(text, limit=MAX_COMMAND_CHARS):
    text = _safe(text)
    if len(text) <= limit:
        return html.escape(text)
    dropped = len(text) - limit
    return (html.escape(text[:limit])
            + f"\n... +{dropped} more character(s) not rendered here, see the JSON export")


def _truncate(text, width):
    # Sanitise before cutting, so the cut cannot leave a half-formed escape.
    text = " ".join(_safe(text).split())
    return text if len(text) <= width else text[: width - 3] + "..."


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

def write_html(path, alerts, cases, meta):
    # Render first: opening the file first truncates a good report if this raises.
    document = _html_document(alerts, cases, meta)
    write_text(path, document)
    return path


def write_text(path, text):
    """Write a report so a failure can never destroy the previous one.

    Rendering to a string first is not enough, because a lone surrogate survives
    json.load and fails the encode mid-write. Temp file plus rename leaves the
    destination as either the old report or the whole new one.
    """
    target = os.path.abspath(path)
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    temp = target + ".part"
    try:
        with open(temp, "w", encoding="utf-8", errors="replace") as handle:
            handle.write(text)
        os.replace(temp, target)
    except BaseException:
        try:
            os.remove(temp)
        except OSError:
            pass
        raise
    return target


def _dial(score, band_name):
    """Risk dial as a conic gradient: pure CSS, so no images and no script."""
    degrees = int(round(score / 100 * 360))
    color = BAND_HEX.get(band_name, "#6b7280")
    return (f'<div class="dial" style="background:conic-gradient({color} {degrees}deg,'
            f'#e3e6ea {degrees}deg)"><span>{score}</span></div>')


def _origins(case, e):
    """The affected hosts and the addresses the sessions came from."""
    rows = []
    if case.get("hosts"):
        chips = "".join(f'<span class="asset-chip">{e(h)}</span>' for h in case["hosts"])
        rows.append(f'<div class="origin-row"><span class="origin-label">affected host'
                    f'{"s" if len(case["hosts"]) > 1 else ""}</span>{chips}</div>')

    origins = case.get("origins") or {}
    if origins:
        chips = []
        for ip, meta in sorted(origins.items()):
            scope = meta.get("scope") or "unknown"
            verdict = meta.get("verdict") or "unknown"
            chips.append(
                f'<span class="origin-chip {e(scope)}">{e(ip)}'
                f'<em>{e(scope)} &middot; {e(verdict)}</em></span>'
            )
        rows.append('<div class="origin-row"><span class="origin-label">originated from'
                    '</span>' + "".join(chips) + "</div>")
    return "".join(rows)


def _chain(tactics):
    if not tactics:
        return ""
    steps = "".join(
        f'<li><span class="step-dot"></span>{_h(t)}</li>' for t in tactics
    )
    return f'<ol class="chain">{steps}</ol>'


def _html_document(alerts, cases, meta):
    e = _h

    counts = {}
    for alert in alerts:
        counts[alert["band"]["name"]] = counts.get(alert["band"]["name"], 0) + 1
    tiles = "".join(
        f'<div class="tile {BAND_HTML.get(n, "info")}">'
        f'<span class="tile-n">{counts.get(n, 0)}</span>'
        f'<span class="tile-l">{n}</span></div>'
        for n in ("Critical", "High", "Medium", "Low", "Informational")
    )

    # Cases are ranked, so the tail is the part worth dropping. The per-case caps
    # alone leave the document unbounded: one account per finding is tens of MB.
    shown_cases = cases[:MAX_CASES]
    case_blocks = [
        _case_block(position, case, e) for position, case in enumerate(shown_cases, start=1)
    ]
    if len(cases) > len(shown_cases):
        case_blocks.append(
            '<p class="omitted">The queue holds {} case(s); the {} highest-risk are '
            'rendered here. The rest are in the JSON export.</p>'.format(
                len(cases), len(shown_cases)
            )
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Alert Triage Queue</title>
<style>
:root {{
  --page:#eef1f4; --card:#ffffff; --ink:#1c2530; --muted:#68737f; --line:#dde2e8;
  --band:#16202b;
  --critical:#c62828; --high:#e05d1f; --medium:#b8860b; --low:#2f6f9f; --info:#6b7280;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--page); color:var(--ink);
  font:14px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif; }}
header {{ background:var(--band); color:#eef1f4; padding:26px 34px 22px; }}
header h1 {{ margin:0; font-size:20px; font-weight:600; letter-spacing:.4px; }}
header .lead {{ margin:4px 0 0; color:#9fb0c0; font-size:12.5px; }}
header code {{ color:#d7e3ee; }}
.tiles {{ display:flex; gap:10px; flex-wrap:wrap; margin-top:18px; }}
.tile {{ flex:1 1 110px; background:#1e2b38; border-radius:7px; padding:9px 12px;
  border-left:4px solid var(--info); }}
.tile-n {{ display:block; font-size:21px; font-weight:600; color:#fff; }}
.tile-l {{ font-size:10.5px; text-transform:uppercase; letter-spacing:1.1px; color:#9fb0c0; }}
.tile.critical {{ border-left-color:var(--critical); }} .tile.high {{ border-left-color:var(--high); }}
.tile.medium {{ border-left-color:var(--medium); }} .tile.low {{ border-left-color:var(--low); }}
main {{ padding:26px 34px 50px; max-width:1120px; margin:0 auto; }}

.case {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
  margin-bottom:20px; overflow:hidden; box-shadow:0 1px 2px rgba(20,30,40,.06); }}
.case-top {{ display:flex; gap:18px; padding:18px 20px; align-items:flex-start; }}
.case-top.critical {{ border-top:3px solid var(--critical); }}
.case-top.high {{ border-top:3px solid var(--high); }}
.case-top.medium {{ border-top:3px solid var(--medium); }}
.case-top.low {{ border-top:3px solid var(--low); }}
.case-top.info {{ border-top:3px solid var(--info); }}
.dial {{ width:72px; height:72px; border-radius:50%; display:flex; align-items:center;
  justify-content:center; flex:0 0 72px; }}
.dial span {{ width:54px; height:54px; border-radius:50%; background:var(--card);
  display:flex; align-items:center; justify-content:center; font-size:19px; font-weight:700; }}
.case-main {{ flex:1 1 auto; min-width:0; }}
.case-id {{ font-size:11px; text-transform:uppercase; letter-spacing:1.2px; color:var(--muted); }}
.case-account {{ font-size:18px; font-weight:600; margin:1px 0 6px; }}
.case-summary {{ margin:0 0 10px; color:#39434e; }}
.facts {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:8px; }}
.fact {{ font-size:11.5px; background:#f1f4f7; border:1px solid var(--line);
  border-radius:5px; padding:2px 9px; color:#41505e; }}
.fact b {{ color:var(--ink); font-weight:600; }}
.chain {{ list-style:none; display:flex; flex-wrap:wrap; gap:0; margin:10px 0 6px; padding:0; }}
.chain li {{ font-size:11.5px; color:#41505e; padding:2px 14px 2px 0; position:relative;
  display:flex; align-items:center; gap:6px; }}
.chain li:not(:last-child)::after {{ content:"\\203A"; position:absolute; right:5px; color:#aab4bf; }}
.step-dot {{ width:7px; height:7px; border-radius:50%; background:var(--low); flex:0 0 7px; }}
.origin-row {{ display:flex; align-items:center; gap:7px; flex-wrap:wrap; margin:7px 0 0; }}
.origin-label {{ font-size:10.5px; text-transform:uppercase; letter-spacing:1px;
  color:var(--muted); min-width:104px; }}
.asset-chip {{ font-family:Consolas,monospace; font-size:11.5px; background:#eceff2;
  border:1px solid var(--line); border-radius:4px; padding:2px 8px; color:#33404c; }}
.origin-chip {{ font-family:Consolas,monospace; font-size:11.5px; border-radius:4px;
  padding:2px 8px; border:1px solid var(--line); background:#eceff2; color:#33404c; }}
.origin-chip em {{ font-style:normal; font-family:"Segoe UI",sans-serif; font-size:10px;
  text-transform:uppercase; letter-spacing:.7px; margin-left:7px; opacity:.75; }}
.origin-chip.external {{ background:#fdeceb; border-color:#f2c4c1; color:#8e2620; }}
.origin-chip.internal {{ background:#fff6e0; border-color:#ecd9a6; color:#6d5312; }}
.ioc-chip {{ display:inline-block; font-size:11px; border-radius:4px; padding:2px 8px;
  margin:3px 5px 0 0; font-family:Consolas,monospace; }}
.ioc-chip.malicious {{ background:#fce8e8; color:#8e1f1f; border:1px solid #f0c2c2; }}
.ioc-chip.suspicious {{ background:#fdf0e2; color:#8a4512; border:1px solid #f2d5b6; }}

.case-alerts {{ border-top:1px solid var(--line); background:#f7f9fb; padding:6px 10px 10px; }}
.case-alerts h3 {{ font-size:10.5px; text-transform:uppercase; letter-spacing:1.2px;
  color:var(--muted); margin:10px 10px 6px; font-weight:600; }}
details.alert {{ background:var(--card); border:1px solid var(--line); border-left:3px solid var(--info);
  border-radius:7px; margin:0 0 7px; }}
details.alert.critical {{ border-left-color:var(--critical); }}
details.alert.high {{ border-left-color:var(--high); }}
details.alert.medium {{ border-left-color:var(--medium); }}
details.alert.low {{ border-left-color:var(--low); }}
summary {{ cursor:pointer; padding:9px 13px; display:flex; align-items:center; gap:10px;
  flex-wrap:wrap; list-style:none; }}
summary::-webkit-details-marker {{ display:none; }}
summary::before {{ content:"\\25B8"; color:var(--muted); font-size:11px; }}
details[open] > summary::before {{ content:"\\25BE"; }}
.score-pill {{ font-family:Consolas,monospace; font-size:12px; font-weight:700; color:#fff;
  background:var(--info); border-radius:4px; padding:1px 7px; min-width:34px; text-align:center; }}
.score-pill.critical {{ background:var(--critical); }} .score-pill.high {{ background:var(--high); }}
.score-pill.medium {{ background:var(--medium); }} .score-pill.low {{ background:var(--low); }}
.a-rule {{ font-weight:600; }}
.a-meta {{ font-size:11.5px; color:var(--muted); }}
.a-body {{ padding:2px 14px 15px; border-top:1px solid var(--line); }}
.a-body h4 {{ font-size:10.5px; text-transform:uppercase; letter-spacing:1.1px;
  color:var(--muted); margin:15px 0 5px; }}
.why {{ margin:11px 0; color:#39434e; }}
pre {{ background:#f4f6f8; border:1px solid var(--line); border-radius:5px; padding:9px 11px;
  overflow-x:auto; font-family:Consolas,monospace; font-size:12.5px; margin:6px 0; color:#22303c; }}
pre.decoded {{ border-left:3px solid #7c4dbe; background:#f7f3fc; }}
.grid {{ width:100%; border-collapse:collapse; font-size:12.5px; }}
.grid th {{ text-align:left; color:var(--muted); font-weight:600; font-size:11px;
  text-transform:uppercase; letter-spacing:.6px; border-bottom:1px solid var(--line); padding:5px 8px; }}
.grid td {{ border-bottom:1px solid var(--line); padding:6px 8px; vertical-align:top; }}
.verdict {{ font-size:11px; border-radius:4px; padding:1px 8px; }}
.verdict.malicious {{ background:#fce8e8; color:#8e1f1f; }}
.verdict.suspicious {{ background:#fdf0e2; color:#8a4512; }}
.verdict.clean {{ background:#e6f4ea; color:#1e6b34; }}
.verdict.internal {{ background:#eceff2; color:#4a5560; }}
.verdict.unknown {{ background:#f1f4f7; color:#5a6672; }}
.verdict.asset {{ background:#eceff2; color:#4a5560; }}
.role {{ font-size:10px; text-transform:uppercase; letter-spacing:.7px; border-radius:3px;
  padding:1px 6px; background:#eceff2; color:#5a6672; }}
.role.source {{ background:#e7eefc; color:#26437e; }}
.role.asset {{ background:#f3f0e8; color:#6a5c38; }}
.tag {{ font-size:10.5px; background:#f0eaf9; color:#5b3a8e; border-radius:4px; padding:1px 6px; }}
.breakdown .pts {{ width:50px; font-family:Consolas,monospace; font-weight:700; text-align:right; }}
.mono {{ font-family:Consolas,monospace; word-break:break-all; }}
.muted {{ color:var(--muted); }}
.omitted {{ color:var(--muted); font-size:12.5px; text-align:center; margin:18px 0 0; }}
.action {{ margin:5px 0; padding:8px 11px; background:#f4f6f8; border-left:3px solid var(--low);
  border-radius:0 5px 5px 0; }}
.playbook {{ margin:6px 0 0 18px; padding:0; color:#39434e; }}
.playbook li {{ margin:3px 0; }}
footer {{ border-top:1px solid var(--line); padding:18px 34px; color:var(--muted);
  font-size:11.5px; background:var(--card); }}
/* A printed report is a ticket attachment: every alert body has to be on the
   paper, and the dark chrome re-inked, because browsers drop backgrounds but
   keep the light text that was sitting on them. */
@media print {{
  @page {{ margin:14mm; }}
  body {{ background:#fff; }}
  main {{ padding:14px 0 0; max-width:none; }}
  /* Closed <details> are hidden by the browser, by a mechanism that differs per
     engine, so unhide both the pseudo-element and the children directly or the
     paper shows summaries and nothing else. */
  details.alert > *:not(summary) {{ display:block !important; }}
  details.alert::details-content {{ content-visibility:visible !important;
    block-size:auto !important; }}
  summary::before, details[open] > summary::before {{ display:none; }}
  /* An alert body can outrun a page, so forbid only the breaks that strand a
     heading from what it heads. */
  summary {{ cursor:auto; break-after:avoid; page-break-after:avoid; }}
  .case {{ box-shadow:none; }}
  .case-top {{ break-inside:avoid; page-break-inside:avoid; break-after:avoid; }}
  .a-body h4 {{ break-after:avoid; page-break-after:avoid; }}
  pre {{ white-space:pre-wrap; word-break:break-all; }}
  header {{ background:#fff; color:#1c2530; border-bottom:2px solid #1c2530;
    padding:0 0 12px; break-after:avoid; }}
  header .lead {{ color:#41505e; }}
  header code {{ color:#1c2530; }}
  .tile {{ background:#fff; border:1px solid #dde2e8; }}
  .tile-n {{ color:#1c2530; }}
  .tile-l {{ color:#41505e; }}
  .score-pill {{ background:#fff !important; color:#1c2530; border:1px solid #1c2530; }}
  .verdict, .role, .tag, .fact, .asset-chip, .origin-chip {{ border:1px solid #c8ced5;
    color:#1c2530; background:#fff; }}
  .dial {{ border:2px solid #1c2530; }}
  footer {{ break-inside:avoid; page-break-inside:avoid; padding:14px 0; }}
}}
</style></head><body>
<header>
  <h1>Alert Triage Queue</h1>
  <p class="lead">
    {len(alerts)} alert(s) folded into {len(cases)} case(s) &middot; generated {e(meta['generated'])}
    &middot; engine v{e(meta['version'])}<br>
    Intake <code>{e(meta['input'])}</code> ({meta['finding_count']} finding(s))
    &middot; enrichment: {e(meta['enrichment'])}
    &middot; {meta['lookups']} indicator lookup(s), {meta['cache_hits']} cached
  </p>
  <div class="tiles">{tiles}</div>
</header>
<main>
{''.join(case_blocks)}
</main>
<footer>
  Work the cases top to bottom &mdash; each one is a single decision, not a row to close.<br>
  Recommendations only: this tool reads and scores, it never contains, blocks or changes anything.
  Verdicts are pattern matches and third-party reputation, not proof of compromise.<br>
  So this file stays small enough to attach to a ticket it renders at most
  {MAX_CASES} case(s), {MAX_ALERTS_PER_CASE} alert(s) per case, {MAX_IOC_ROWS} indicator
  row(s) per alert and {MAX_COMMAND_CHARS} character(s) of any one command line; anything
  past that is marked in place and kept in full in the JSON export.<br>
  Written by Baris Burak Turgut &middot; MIT License &middot; provided &quot;AS IS&quot;, without warranty of any kind.
</footer>
</body></html>
"""


def _case_block(position, case, e):
    cls = BAND_HTML.get(case["band"]["name"], "info")
    chips = "".join(
        f'<span class="ioc-chip {e(verdict)}">{e(value)}</span>'
        for value, verdict in sorted(case["bad_indicators"].items())
    )
    shown = case.get("shown_count", case["alert_count"])
    hidden = case["alert_count"] - shown

    rendered = case["alerts"][:MAX_ALERTS_PER_CASE]
    clipped = len(case["alerts"]) - len(rendered)
    notes = []
    if hidden:
        notes.append(f"{hidden} below the reporting threshold")
    if clipped:
        notes.append(f"{clipped} more not rendered here, see the JSON export")
    hidden_note = f' <span class="muted">({"; ".join(notes)})</span>' if notes else ""

    alerts_html = "".join(_alert_block(alert, e) for alert in rendered)

    return f"""
  <section class="case">
    <div class="case-top {cls}">
      {_dial(case['score'], case['band']['name'])}
      <div class="case-main">
        <div class="case-id">Case #{position} &middot; {e(case['band']['name'])}</div>
        <div class="case-account">{html.escape(_account(case))}</div>
        <p class="case-summary">{e(case['summary'])}</p>
        <div class="facts">
          <span class="fact">queue <b>{e(case['band']['queue'])}</b></span>
          <span class="fact">SLA <b>{e(_sla(case['band']))}</b></span>
          <span class="fact">account <b>{e(case['account_type'])}</b></span>
          <span class="fact">alerts <b>{case['alert_count']}</b></span>
          <span class="fact">window <b>{e(case['first_seen'] or '?')} &ndash; {e(case['last_seen'] or '?')}</b></span>
        </div>
        {_origins(case, e)}
        {_chain(case['tactics'])}
        <div>{chips}</div>
      </div>
    </div>
    <div class="case-alerts">
      <h3>Alerts in this case ({len(rendered)} of {shown}){hidden_note}</h3>
      {alerts_html}
    </div>
  </section>"""


def _alert_block(alert, e):
    finding = alert["finding"]
    cls = BAND_HTML.get(alert["band"]["name"], "info")

    ioc_rows = []
    for ioc in alert["iocs"][:MAX_IOC_ROWS]:
        intel = ioc.get("intel") or {}
        verdict = intel.get("verdict") or "unknown"
        role = ioc.get("role") or "destination"
        tag = '<span class="tag">via decode</span>' if ioc["via_decode"] else ""
        ioc_rows.append(
            f'<tr><td><span class="role {e(role)}">{e(role)}</span></td>'
            f'<td>{e(ioc["type"])}</td><td class="mono">{e(ioc["value"])}</td>'
            f'<td><span class="verdict {e(verdict)}">{e(verdict)}</span> {tag}</td>'
            f'<td class="muted">{e(intel.get("note") or "")}</td></tr>'
        )
    extra_iocs = len(alert["iocs"]) - len(ioc_rows)
    if extra_iocs > 0:
        ioc_rows.append(f'<tr><td colspan="5" class="muted">+{extra_iocs} more indicator(s) '
                        f'not rendered here, see the JSON export</td></tr>')
    iocs = "".join(ioc_rows) or '<tr><td colspan="5" class="muted">no indicators referenced</td></tr>'

    context_bits = []
    if alert.get("host"):
        context_bits.append(f'<span class="fact">host <b>{e(alert["host"])}</b></span>')
    if alert.get("source_ip"):
        scope = alert.get("source_scope") or "unknown"
        context_bits.append(
            f'<span class="fact">from <b>{e(alert["source_ip"])}</b> ({e(scope)})</span>'
        )
    if alert.get("logon_type"):
        context_bits.append(f'<span class="fact">logon type <b>{e(alert["logon_type"])}</b></span>')
    context = f'<div class="facts">{"".join(context_bits)}</div>' if context_bits else ""

    breakdown = "".join(
        f'<tr><td class="pts">{"+" if i["points"] >= 0 else ""}{i["points"]}</td>'
        f'<td><strong>{e(i["label"])}</strong><br><span class="muted">{e(i["reason"])}</span></td></tr>'
        for i in alert["contributions"]
    )
    if alert["raw_score"] != alert["score"]:
        breakdown += (f'<tr><td class="pts muted">=</td><td class="muted">raw '
                      f'{alert["raw_score"]} clamped to {alert["score"]}</td></tr>')

    decoded = "".join(f'<pre class="decoded">{_clip(d)}</pre>' for d in alert["decoded"])
    playbook = "".join(f"<li>{e(step)}</li>" for step in alert["playbook"])
    command = _safe(finding.get("CommandLine"))

    return f"""
      <details class="alert {cls}">
        <summary>
          <span class="score-pill {cls}">{alert['score']}</span>
          <span class="a-rule">{e(finding.get('Rule'))}</span>
          <span class="a-meta">{e(finding.get('Time')) or '?'} &middot; {e(finding.get('Attack'))}</span>
        </summary>
        <div class="a-body">
          <p class="why">{e(finding.get('Why'))}</p>
          <p class="a-meta">log channel {e(finding.get('Source'))} &middot;
             {e(alert['id'])} &middot; detection severity {e(finding.get('Severity'))}</p>
          {context}
          {f'<pre>{_clip(command)}</pre>' if command.strip() else ''}
          {decoded}
          <h4>Indicators</h4>
          <table class="grid"><tr><th>Role</th><th>Type</th><th>Value</th><th>Verdict</th><th>Note</th></tr>{iocs}</table>
          <h4>Why this score</h4>
          <table class="grid breakdown">{breakdown}</table>
          <h4>Recommended next steps</h4>
          <p class="action">{e(alert['recommended_action'])}</p>
          <ol class="playbook">{playbook}</ol>
        </div>
      </details>"""
