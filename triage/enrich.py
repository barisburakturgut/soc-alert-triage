"""
Threat-intelligence enrichment. Two provider modes behind one interface:

  offline  - samples/mock-intel.json. No key, no network, and the default.
  live     - AbuseIPDB for IPs, VirusTotal for domains and hashes, each enabled
             only when its API key is in the environment.

Stdlib only. Results are cached because free tiers are rate-limited and one C2
address turns up in half the findings.
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

VERDICTS = ("malicious", "suspicious", "unknown", "clean", "internal", "asset")

_UNKNOWN = {
    "verdict": "unknown",
    "confidence": 0,
    "provider": "none",
    "note": "no reputation data available",
}

# Reputation moves: yesterday's "clean" is worth re-asking.
CACHE_TTL_SECONDS = 24 * 3600

_SECRET_HEADERS = ("key", "x-apikey", "authorization")

# Bookkeeping the pipeline needs but a report must never show.
_INTERNAL_KEYS = ("transient", "snapshot")


class _StripAuthOnCrossOriginRedirect(urllib.request.HTTPRedirectHandler):
    """Follows redirects, but never hands the API key to a host we did not choose."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = urllib.request.HTTPRedirectHandler.redirect_request(
            self, req, fp, code, msg, headers, newurl
        )
        if new is None:
            return None
        old, target = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if target.scheme != "https":
            return None  # a lookup is never worth carrying onto plaintext
        if (target.scheme, target.netloc.lower()) != (old.scheme, old.netloc.lower()):
            # urllib capitalises header names on the way in.
            for name in list(new.headers):
                if name.lower() in _SECRET_HEADERS:
                    del new.headers[name]
        return new


_OPENER = urllib.request.build_opener(_StripAuthOnCrossOriginRedirect())


class OfflineProvider:
    """Serves verdicts from a bundled JSON snapshot."""

    name = "offline"
    supports = ("ip", "domain", "hash")

    def __init__(self, snapshot_path):
        with open(snapshot_path, "r", encoding="utf-8") as handle:
            self._data = json.load(handle)

    def lookup(self, ioc_type, value):
        table = self._data.get(ioc_type) or {}
        hit = table.get(value.lower())
        # Flagged so the cache refuses it; a fixture must not outlive its run.
        if hit is None:
            return dict(_UNKNOWN, provider="offline-snapshot", snapshot=True)
        return dict(hit, snapshot=True)


class AbuseIPDBProvider:
    """IP reputation via AbuseIPDB. Requires ABUSEIPDB_API_KEY."""

    name = "abuseipdb"
    supports = ("ip",)
    endpoint = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key, timeout=10):
        self.api_key = api_key
        self.timeout = timeout

    def lookup(self, ioc_type, value):
        query = urllib.parse.urlencode({"ipAddress": value, "maxAgeInDays": 90})
        request = urllib.request.Request(
            f"{self.endpoint}?{query}",
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        payload = _get_json(request, self.timeout)
        if payload is None:
            return dict(_UNKNOWN, provider="abuseipdb",
                        note="lookup failed or rate-limited", transient=True)

        data = payload.get("data", {})
        score = int(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)

        if reports == 0:
            verdict = "unknown"
        elif score >= 50:
            verdict = "malicious"
        elif score >= 15:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "verdict": verdict,
            "confidence": score,
            "provider": "abuseipdb",
            "categories": [],
            "country": data.get("countryCode"),
            "total_reports": reports,
            "last_reported": data.get("lastReportedAt"),
            "note": f"{reports} report(s), abuse confidence {score}%",
        }


class VirusTotalProvider:
    """Domain and file-hash reputation via VirusTotal. Requires VIRUSTOTAL_API_KEY."""

    name = "virustotal"
    supports = ("domain", "hash", "ip")
    _paths = {"domain": "domains", "hash": "files", "ip": "ip_addresses"}

    def __init__(self, api_key, timeout=10):
        self.api_key = api_key
        self.timeout = timeout

    def lookup(self, ioc_type, value):
        path = self._paths.get(ioc_type)
        if path is None:
            return dict(_UNKNOWN, provider="virustotal")

        request = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/{path}/{urllib.parse.quote(value)}",
            headers={"x-apikey": self.api_key, "Accept": "application/json"},
        )
        payload = _get_json(request, self.timeout)
        if payload is None:
            return dict(_UNKNOWN, provider="virustotal",
                        note="lookup failed or rate-limited", transient=True)

        stats = (payload.get("data", {}).get("attributes", {}).get("last_analysis_stats")) or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        total = sum(int(v or 0) for v in stats.values())

        if malicious >= 5:
            verdict = "malicious"
        elif malicious >= 1 or suspicious >= 2:
            verdict = "suspicious"
        elif total > 0:
            verdict = "clean"
        else:
            verdict = "unknown"

        confidence = int(round(100 * malicious / total)) if total else 0
        return {
            "verdict": verdict,
            "confidence": confidence,
            "provider": "virustotal",
            "categories": [],
            "detections": f"{malicious}/{total} engines" if total else "no engine data",
            "note": f"{malicious} malicious / {suspicious} suspicious of {total} engines",
        }


def _get_json(request, timeout):
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError, OSError):
        return None


class Enricher:
    """Routes each IOC to the first provider that supports its type, with caching."""

    def __init__(self, providers, cache_path=None, pause_seconds=0.0,
                 ttl_seconds=CACHE_TTL_SECONDS, mode="offline"):
        self.providers = list(providers)
        self.cache_path = cache_path
        self.pause_seconds = pause_seconds
        self.ttl_seconds = ttl_seconds
        self.mode = mode
        self._cache, self._fetched = _load_cache(cache_path, ttl_seconds)
        # Counted so the report can name the provider behind every verdict.
        self.stats = {"lookups": 0, "cache_hits": 0, "queried": 0, "providers": {}}

    def enrich(self, ioc):
        ioc_type, value = ioc["type"], ioc["value"]

        # Looking up the affected machine would score it against its own name.
        if ioc.get("role") == "asset":
            return {
                "verdict": "asset",
                "confidence": 0,
                "provider": "local",
                "note": "the affected host itself - not an external indicator",
            }

        if ioc_type == "url":
            return dict(_UNKNOWN, provider="n/a", note="URL kept as context; its host is enriched separately")

        if ioc.get("scope") in ("internal", "loopback", "reserved"):
            return {
                "verdict": "internal",
                "confidence": 0,
                "provider": "local",
                "note": f"{ioc.get('scope')} address - no external reputation applies",
            }

        # "unknown" rather than "internal": the link-local metadata endpoint must
        # not collect the discount RFC1918 space gets two branches up.
        if ioc.get("scope") == "link_local":
            return dict(
                _UNKNOWN,
                provider="local",
                note="link-local address - no external reputation applies",
            )

        self.stats["lookups"] += 1
        # Keyed by mode too: a demo run must never answer for a live one.
        cache_key = f"{self.mode}|{ioc_type}:{value.lower()}"
        if cache_key in self._cache:
            self.stats["cache_hits"] += 1
            return self._served(self._cache[cache_key])

        result = dict(_UNKNOWN)
        for provider in self.providers:
            if ioc_type not in provider.supports:
                continue
            result = provider.lookup(ioc_type, value)
            self.stats["queried"] += 1
            if self.pause_seconds and provider.name != "offline":
                time.sleep(self.pause_seconds)
            if result.get("verdict") != "unknown":
                break

        self._cache[cache_key] = result
        return self._served(result)

    def _served(self, result):
        name = result.get("provider") or "unknown"
        self.stats["providers"][name] = self.stats["providers"].get(name, 0) + 1
        return _public(result)

    def save_cache(self):
        if not self.cache_path:
            return
        # Caching a failed lookup turns one bad minute into a lasting false
        # negative, and a cached snapshot verdict would later read as a fetched
        # one. Entries keep their original fetch time, so re-running a batch
        # cannot roll the expiry forward.
        now = int(time.time())
        keepers = {
            key: {"fetched": self._fetched.get(key, now), "result": result}
            for key, result in self._cache.items()
            if not result.get("transient")
            and not result.get("snapshot")
            and result.get("verdict") != "unknown"
        }
        # An offline run keeps nothing, so it never creates the file at all.
        if not keepers and not os.path.exists(self.cache_path):
            return
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as handle:
                json.dump(keepers, handle, indent=2)
        except OSError:
            pass  # an unwritable cache costs a rerun some API calls, nothing more


def _public(result):
    """The caller's copy, with the internal bookkeeping keys stripped."""
    return {key: value for key, value in result.items() if key not in _INTERNAL_KEYS}


def _load_cache(path, ttl_seconds=CACHE_TTL_SECONDS):
    """Returns (results by key, fetch time by key). Anything past its TTL is dropped."""
    if not path or not os.path.exists(path):
        return {}, {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}, {}
    if not isinstance(data, dict):
        return {}, {}

    fresh, stamps, now = {}, {}, time.time()
    for key, entry in data.items():
        # A hand-edited cache must not crash the run. A key with no mode prefix
        # predates namespacing, so nothing says which mode wrote it.
        if not isinstance(key, str) or "|" not in key or not isinstance(entry, dict):
            continue
        result, fetched = entry.get("result"), entry.get("fetched")
        if not isinstance(result, dict) or not isinstance(fetched, (int, float)):
            continue
        if result.get("verdict") not in VERDICTS or now - fetched > ttl_seconds:
            continue
        fresh[key] = result
        stamps[key] = fetched
    return fresh, stamps


def build_enricher(mode, snapshot_path, cache_path=None):
    """Assemble the provider chain for a mode. Returns (enricher, description).

    In live mode an indicator type with no key falls back to the snapshot rather
    than silently returning 'unknown'.
    """
    offline = OfflineProvider(snapshot_path)
    if mode == "offline":
        return (
            Enricher([offline], cache_path, mode="offline"),
            "offline snapshot (no network, no API keys)",
        )

    providers, active = [], []
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if abuse_key:
        providers.append(AbuseIPDBProvider(abuse_key))
        active.append("AbuseIPDB (IP)")
    if vt_key:
        providers.append(VirusTotalProvider(vt_key))
        active.append("VirusTotal (domain/hash)")

    if not providers:
        # No key means no live data, so use the offline cache namespace rather
        # than seeding a "live" one from fixtures.
        return (
            Enricher([offline], cache_path, mode="offline"),
            "offline snapshot - live mode requested but no API keys found in the environment",
        )

    providers.append(offline)  # last-resort fallback for unsupported types
    return (
        Enricher(providers, cache_path, pause_seconds=1.0, mode="live"),
        "live: " + ", ".join(active) + " (offline snapshot as fallback)",
    )
