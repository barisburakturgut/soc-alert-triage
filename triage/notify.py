"""
Webhook notification: the end of the pipeline that reaches a human.

Only cases at or above `notify_min_band` are sent. A channel that gets posted to
for everything is muted within a week, and the real one is missed with it.

Slack, Discord and Teams shapes, inferred from the URL. `--dry-run` prints the
payload instead of sending it.
"""

import html
import http.client
import json
import re
import urllib.error
import urllib.request

from . import report

# Chat platforms render these payloads as rich text, so every value lifted from
# a finding is untrusted: an attacker-chosen filename must not become an
# @channel broadcast or a disguised link.
_MAX_INDICATORS = 20
_SECTION_LIMITS = {"slack": 3000, "discord": 4096, "teams": 20000}
_DISCORD_TOTAL_LIMIT = 6000

_BAND_COLOR = {
    "Critical": 0xFF4D4F,
    "High": 0xFF7B3D,
    "Medium": 0xF0C000,
    "Low": 0x3FB6FF,
    "Informational": 0x6E7681,
}


def detect_platform(url):
    lowered = (url or "").lower()
    if "hooks.slack.com" in lowered:
        return "slack"
    if "discord.com" in lowered or "discordapp.com" in lowered:
        return "discord"
    if "webhook.office.com" in lowered or "office.com" in lowered or "logic.azure.com" in lowered:
        return "teams"
    return "slack"


def _plain(text):
    """Flatten to one line, neutralise, then defuse the broadcast tokens.

    Order matters: str.split() only breaks on whitespace, so bidi overrides are
    neutralise's job, and the zero-width defusal goes last or neutralise strips it.
    """
    out = " ".join(report.neutralise(text).split())
    return out.replace("@everyone", "@​everyone").replace("@here", "@​here")


def _slack_escape(text):
    # Ampersand first, or the angle brackets get double-encoded.
    return _plain(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _teams_escape(text):
    return html.escape(_plain(text))


def _discord_escape(text):
    out = _plain(text)
    for char in ("\\", "`", "*", "_", "~", "|", ">"):
        out = out.replace(char, "\\" + char)
    return out


_ESCAPERS = {"slack": _slack_escape, "teams": _teams_escape, "discord": _discord_escape}


def _case_account(case, platform="slack"):
    """Falls back through account_key, since a finding may carry User: null."""
    escape = _ESCAPERS.get(platform, _slack_escape)
    return (escape(case.get("account")) or escape(case.get("account_key"))
            or "an unnamed account")


_BOLD = {"slack": "*", "discord": "**", "teams": ""}


def _clip(text, limit):
    if len(text) <= limit:
        return text
    return text[: limit - 14].rstrip() + "\n... truncated"


def _lines(case, platform="slack"):
    escape = _ESCAPERS.get(platform, _slack_escape)
    bold = _BOLD.get(platform, "*")
    names = sorted(case["bad_indicators"])
    indicators = ", ".join(escape(value) for value in names[:_MAX_INDICATORS]) or "none"
    if len(names) > _MAX_INDICATORS:
        # Keep the count, or the message understates the case.
        indicators += f", +{len(names) - _MAX_INDICATORS} more"
    window = (f"between {escape(case['first_seen'])} and {escape(case['last_seen'])}"
              if case.get("first_seen") and case.get("last_seen") else "at an unrecorded time")
    return [
        f"{bold}Account:{bold} {_case_account(case, platform)} ({escape(case['account_type'])})",
        f"{bold}Risk:{bold} {case['score']}/100 - {escape(case['band']['name'])} -> {escape(case['band']['queue'])}",
        f"{bold}Alerts:{bold} {case['alert_count']} {window}",
        f"{bold}ATT&CK chain:{bold} {' -> '.join(escape(t) for t in case['tactics']) or 'n/a'}",
        f"{bold}Known-bad indicators:{bold} {indicators}",
        f"_{escape(case['summary'])}_",
    ]


def build_payload(cases, platform, source_label):
    title = f"SOC Alert Triage - {len(cases)} case(s) need attention"

    if platform == "discord":
        # Discord rejects the whole message over 6000 chars across all embeds, so
        # track the budget while building, leaving room for the truncation note.
        budget = _DISCORD_TOTAL_LIMIT - 200
        embeds, omitted = [], 0
        for case in cases[:10]:
            embed_title = (f"{_plain(case['band']['name'])} - {_case_account(case, 'discord')}"
                           f"  ({case['score']}/100)")
            footer = f"source: {_plain(source_label)}"
            text = _clip("\n".join(_lines(case, "discord")), _SECTION_LIMITS["discord"])
            cost = len(embed_title) + len(text) + len(footer)
            if omitted or cost > budget:
                omitted += 1
                continue
            budget -= cost
            embeds.append({
                "title": embed_title,
                "description": text,
                "color": _BAND_COLOR.get(case["band"]["name"], 0x6E7681),
                "footer": {"text": footer},
            })
        if omitted:
            embeds.append({
                "title": "Truncated",
                "description": f"{omitted} further case(s) omitted - see the full report.",
                "color": 0x6E7681,
            })
        return {"username": "SOC Alert Triage", "embeds": embeds}

    if platform == "teams":
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": title,
            "themeColor": f"{_BAND_COLOR.get(cases[0]['band']['name'], 0x6E7681):06X}",
            "title": title,
            "sections": [
                {
                    "activityTitle": (f"{_teams_escape(case['band']['name'])} - "
                                      f"{_case_account(case, 'teams')} ({case['score']}/100)"),
                    "text": _clip("<br>".join(_lines(case, "teams")), _SECTION_LIMITS["teams"]),
                }
                for case in cases[:10]
            ],
        }

    # Slack (default)
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": title}}]
    for case in cases[:10]:
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": _clip("\n".join(_lines(case, "slack")), _SECTION_LIMITS["slack"]),
            },
        })
    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn",
                      "text": f"source: `{_slack_escape(source_label)}` - recommendations only"}],
    })
    return {"text": title, "blocks": blocks}


_BAD_URL_CHARS = re.compile(r"[\s\x00-\x1f\x7f]")


def send(url, payload, timeout=10):
    """POST the payload. Returns (ok, message).

    A webhook path is the whole secret, so the URL never reaches the message or
    a traceback.
    """
    url = (url or "").strip()
    if not url.lower().startswith(("http://", "https://")) or _BAD_URL_CHARS.search(url):
        return False, "invalid webhook URL (expected an http(s):// URL with no whitespace)"
    data = json.dumps(payload).encode("utf-8")
    try:
        request = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return True, f"HTTP {response.status}"
    except urllib.error.HTTPError as error:
        return False, f"HTTP {error.code}: {error.reason}"
    except (urllib.error.URLError, TimeoutError, OSError,
            http.client.HTTPException, ValueError) as error:
        return False, type(error).__name__
