"""Command-line entry point."""

import argparse
import json
import os
import re
import sys
import webbrowser
from datetime import datetime

from . import __version__, engine, notify, report
from .enrich import build_enricher
from .score import band_rank

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULTS = {
    "input": os.path.join(ROOT, "samples", "findings.json"),
    "config": os.path.join(ROOT, "config", "triage.json"),
    "snapshot": os.path.join(ROOT, "samples", "mock-intel.json"),
    "cache": os.path.join(ROOT, ".cache", "intel-cache.json"),
}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="soc-triage",
        description=(
            "Triage detection findings: extract indicators, enrich them with threat "
            "intelligence, score each alert with a visible breakdown, correlate them "
            "into per-account cases, and report. Recommendations only - never acts."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python soc-triage.py\n"
            "      triage the bundled sample findings offline\n\n"
            "  python soc-triage.py -i hunt.json --html reports\\triage.html --open\n"
            "      triage a Windows Log Threat Hunter export and open the report\n\n"
            "  python soc-triage.py --intel live --json reports\\triage.json\n"
            "      use AbuseIPDB / VirusTotal (reads API keys from the environment)\n\n"
            "  python soc-triage.py --notify <webhook-url> --dry-run\n"
            "      show exactly what would be posted to Slack / Discord / Teams\n"
        ),
    )
    parser.add_argument("-i", "--input", default=DEFAULTS["input"],
                        help="findings JSON to triage (default: bundled samples)")
    parser.add_argument("-c", "--config", default=DEFAULTS["config"],
                        help="triage configuration (scoring weights, playbooks)")
    parser.add_argument("--intel", choices=("offline", "live"), default="offline",
                        help="enrichment mode; 'live' needs ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEY")
    parser.add_argument("--snapshot", default=DEFAULTS["snapshot"],
                        help="offline threat-intel snapshot")
    parser.add_argument("--no-cache", action="store_true", help="do not read or write the lookup cache")
    parser.add_argument("--min-band", default="Informational",
                        choices=("Critical", "High", "Medium", "Low", "Informational"),
                        help="only report alerts at or above this band")
    parser.add_argument("--html", metavar="PATH", help="write a self-contained HTML report")
    parser.add_argument("--json", metavar="PATH", help="write the machine-readable result")
    parser.add_argument("--open", action="store_true", help="open the HTML report when done")
    parser.add_argument("--notify", metavar="WEBHOOK_URL", nargs="?", const="",
                        help="post high-risk cases to a Slack / Discord / Teams webhook; "
                             "pass the flag with no URL to use TRIAGE_WEBHOOK_URL")
    parser.add_argument("--notify-format", choices=("slack", "discord", "teams"),
                        help="override webhook format detection")
    parser.add_argument("--dry-run", action="store_true",
                        help="with --notify, print the payload instead of sending it")
    parser.add_argument("--quiet", action="store_true", help="suppress the console report")
    parser.add_argument("--no-breakdown", action="store_true",
                        help="hide the per-alert score breakdown in the console")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--version", action="version", version=f"soc-triage {__version__}")
    return parser


_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _load_dotenv(path=os.path.join(ROOT, ".env")):
    """Read KEY=VALUE lines from .env into the environment.

    Hand-rolled because python-dotenv would cost the zero-dependency property for
    twenty lines of parsing. Existing variables win, so a shell export beats it.
    """
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                # People paste `export KEY=...` straight in; honour it rather
                # than inventing a variable named "export KEY".
                if key.lower().startswith("export "):
                    key = key[7:].strip()
                elif key.lower().startswith("set "):
                    key = key[4:].strip()
                if not _ENV_KEY.match(key):
                    continue
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]  # only a matched pair - a key may end in a quote
                else:
                    # Only after whitespace: a '#' inside a key is part of it.
                    value = re.sub(r"\s+#.*$", "", value).strip()
                if key and value and key not in os.environ:
                    os.environ[key] = value
    except OSError:
        pass


def _write(writer, label, path, *args):
    """A disconnected drive or a bad path is a mistake, not a stack trace."""
    try:
        writer(path, *args)
    except OSError as error:
        sys.stderr.write(f"error: could not write the {label} to {path}: {error}\n")
        raise SystemExit(2)
    print(f"{label} written to {path}")


def _looks_like_finding(value):
    return any(key in value for key in ("Severity", "RuleId", "Rule", "CommandLine"))


def _load_json(path, label):
    if not os.path.exists(path):
        sys.stderr.write(f"error: {label} not found: {path}\n")
        raise SystemExit(2)
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            text = handle.read()
    except OSError as error:
        sys.stderr.write(f"error: {label} could not be read ({path}): {error}\n")
        raise SystemExit(2)
    # A hunt that matched nothing writes an empty file, which is a clean result
    # rather than a broken one.
    if not text.strip():
        return []
    try:
        return json.loads(text)
    except ValueError as error:
        sys.stderr.write(f"error: {label} is not valid JSON ({path}): {error}\n")
        raise SystemExit(2)


_JSON_TYPES = {
    str: "a string", int: "a number", float: "a number",
    bool: "a boolean", list: "an array", type(None): "null",
}

# Every top-level key the pipeline indexes into rather than .get()s. The config
# is meant to be edited, so a missing key owes the reader a sentence.
_REQUIRED_CONFIG = (
    "severity_base", "intel_modifiers", "context_modifiers",
    "correlation_modifiers", "account_patterns", "business_hours", "risk_bands",
)
_REQUIRED_BUSINESS_HOURS = ("start_hour", "end_hour", "workdays")


def _short(path):
    """Bundled files read better as 'config\\triage.json' than as a full path."""
    absolute = os.path.abspath(path)
    return os.path.relpath(absolute, ROOT) if absolute.startswith(ROOT + os.sep) else path


def _fail(message):
    sys.stderr.write(f"error: {message}\n")
    raise SystemExit(2)


def _check_findings(findings, path):
    """Every element has to be an object; a truncated export deserves a message."""
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            found = _JSON_TYPES.get(type(finding), "a non-object value")
            _fail(f"input findings[{index}] is {found}, expected a JSON object ({path})")


def _check_config(config, path):
    if not isinstance(config, dict):
        _fail(f"{path} must be a JSON object")
    for key in _REQUIRED_CONFIG:
        if key not in config:
            _fail(f"{path} is missing \"{key}\"")
    for key in _REQUIRED_CONFIG:
        if key != "risk_bands" and not isinstance(config[key], dict):
            _fail(f"{path}: \"{key}\" must be an object")

    for key in _REQUIRED_BUSINESS_HOURS:
        if key not in config["business_hours"]:
            _fail(f"{path} is missing \"business_hours.{key}\"")

    bands = config["risk_bands"]
    if not isinstance(bands, list) or not bands:
        _fail(f"{path}: \"risk_bands\" must be a non-empty array of bands")
    for index, band in enumerate(bands):
        if not isinstance(band, dict) or not isinstance(band.get("name"), str) or not band["name"]:
            _fail(f"{path}: risk_bands[{index}] needs a non-empty \"name\"")
        if isinstance(band.get("min_score"), bool) or not isinstance(band.get("min_score"), (int, float)):
            _fail(f"{path}: risk_bands[{index}] (\"{band['name']}\") needs a numeric \"min_score\"")
    # Band order is not required - banding sorts by min_score - but a floor at
    # zero is, or a low score falls through every band with nowhere to go.
    scores = [b["min_score"] for b in bands]
    if min(scores) > 0:
        _fail(f"{path}: one band in \"risk_bands\" must have \"min_score\": 0 "
              "so every score falls into a band")

    # An unrecognised threshold matches nothing, so every case would notify.
    notify_band = config.get("notify_min_band", "High")
    names = [b["name"] for b in bands]
    if notify_band not in names:
        _fail(f"{path}: \"notify_min_band\": \"{notify_band}\" is not one of the "
              f"configured risk_bands ({', '.join(names)})")


def _served_by(stats):
    """Name the provider behind every verdict.

    "enrichment: live" states intent, so a live run served entirely by the
    snapshot has to be readable as such from the report alone.
    """
    counts = stats.get("providers") or {}
    if not counts:
        return ""
    ranked = sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
    return "  [verdicts from: " + ", ".join(f"{name} x{n}" for name, n in ranked) + "]"


def main(argv=None):
    args = build_parser().parse_args(argv)
    report.enable_color(not args.no_color)
    _load_dotenv()
    if args.notify == "":  # --notify given with no URL
        args.notify = os.environ.get("TRIAGE_WEBHOOK_URL", "").strip()
        if not args.notify:
            sys.stderr.write("error: --notify needs a URL, or TRIAGE_WEBHOOK_URL in the environment\n")
            raise SystemExit(2)

    findings = _load_json(args.input, "input findings")
    if isinstance(findings, dict):
        if _looks_like_finding(findings):
            # PowerShell's ConvertTo-Json emits a bare object, not a one-element
            # array, when a hunt matched exactly once. Reading that as "nothing to
            # triage" would drop a real finding without saying so.
            findings = [findings]
        else:
            findings = findings.get("findings") or findings.get("alerts") or []
    if not isinstance(findings, list):
        sys.stderr.write("error: expected a JSON array of findings\n")
        raise SystemExit(2)
    if not findings:
        print("No findings in input - nothing to triage.")
        return 0
    _check_findings(findings, _short(args.input))

    config = _load_json(args.config, "triage config")
    _check_config(config, _short(args.config))
    cache_path = None if args.no_cache else DEFAULTS["cache"]
    enricher, enrichment_label = build_enricher(args.intel, args.snapshot, cache_path)
    if args.intel == "live":
        # Falling back to the snapshot fails open, so it is said on stderr, where
        # --quiet cannot hide it.
        if not enrichment_label.startswith("live: "):
            sys.stderr.write(f"warning: {enrichment_label}\n")
        else:
            for name, kind in (("ABUSEIPDB_API_KEY", "IP"), ("VIRUSTOTAL_API_KEY", "domain/hash")):
                if not os.environ.get(name, "").strip():
                    sys.stderr.write(
                        f"warning: {name} is not set - {kind} lookups use the offline snapshot\n")

    alerts, cases = engine.run(findings, config, enricher)
    enricher.save_cache()

    # Decided before --min-band hides anything: the exit code describes the batch,
    # not the console.
    needs_a_human = any(
        band_rank(c["band"]["name"], config) <= band_rank("High", config) for c in cases
    )

    threshold = band_rank(args.min_band, config)
    kept = {id(a) for a in alerts if band_rank(a["band"]["name"], config) <= threshold}
    alerts = [a for a in alerts if id(a) in kept]
    for case in cases:
        # Cases render their own alerts, so the filter has to reach inside them.
        case["alerts"] = [a for a in case["alerts"] if id(a) in kept]
        case["shown_count"] = len(case["alerts"])
    cases = [c for c in cases if c["alerts"]]
    if needs_a_human and not any(
        band_rank(c["band"]["name"], config) <= band_rank("High", config) for c in cases
    ):
        sys.stderr.write(f"warning: --min-band {args.min_band} hides a case at High or above; "
                         "the exit code still reports it\n")

    meta = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "version": __version__,
        "input": os.path.relpath(args.input, ROOT) if args.input.startswith(ROOT) else args.input,
        "finding_count": len(findings),
        "enrichment": enrichment_label + _served_by(enricher.stats),
        "lookups": enricher.stats["lookups"],
        "cache_hits": enricher.stats["cache_hits"],
        "min_band": args.min_band,
    }

    if not args.quiet:
        report.print_console(alerts, cases, meta, show_breakdown=not args.no_breakdown)

    if args.json:
        document = engine.to_serializable(alerts, cases, meta)
        # Serialised in full before the write; see report.write_text.
        _write(report.write_text, "JSON", args.json,
               json.dumps(document, indent=2, ensure_ascii=False))

    if args.html:
        _write(report.write_html, "HTML report", args.html, alerts, cases, meta)
        if args.open:
            webbrowser.open(f"file:///{os.path.abspath(args.html)}".replace("\\", "/"))

    if args.notify:
        _notify(args, cases, config, meta)

    # Exit code doubles as a signal for schedulers: 1 = something needs a human.
    return 1 if needs_a_human else 0


def _notify(args, cases, config, meta):
    minimum = band_rank(config.get("notify_min_band", "High"), config)
    worthy = [c for c in cases if band_rank(c["band"]["name"], config) <= minimum]
    if not worthy:
        print(f"Notification skipped: no case reached {config.get('notify_min_band', 'High')}.")
        return

    platform = args.notify_format or notify.detect_platform(args.notify)
    payload = notify.build_payload(worthy, platform, meta["input"])

    if args.dry_run:
        print(f"\n--- {platform} payload ({len(worthy)} case(s)) - dry run, nothing sent ---")
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    ok, message = notify.send(args.notify, payload)
    print(f"Notification to {platform}: {'sent' if ok else 'FAILED'} ({message})")


if __name__ == "__main__":
    raise SystemExit(main())
