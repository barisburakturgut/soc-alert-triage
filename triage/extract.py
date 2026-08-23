"""
IOC extraction.

Pulls IPs, domains, URLs and file hashes out of every string field on a finding.
Two things make it more than a regex sweep.

Decoding: a `-enc` blob looks inert to a plain scan, but the C2 address usually
lives inside it, so the blob is decoded (UTF-16LE, then UTF-8) and re-scanned.
Indicators recovered that way are tagged `via_decode`.

Direction: an address in a command line and an address in a logon event mean
opposite things, so every indicator carries a `role`:

    destination - what the host reached out to (C2, payload host, download URL)
    source      - where the activity originated (RDP/VPN/network logon origin)
    asset       - the affected machine itself

Enrichment and scoring both read the role, and they read it asymmetrically: an
internal source buys none of the reassurance an internal destination does.
"""

import base64
import binascii
import ipaddress
import re

_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>|)\]]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.IGNORECASE
)
_HASH_RE = re.compile(r"\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.IGNORECASE)
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# "10.0.22.1" is a version string that lands in RFC1918 space, so it would be
# enriched as an internal host and discount a real alert. Shape cannot settle it;
# the text before the match has to carry a version cue. A bare "v" must sit flush
# against the number, or "-v 10.0.0.5" reads as a version.
_VERSION_CONTEXT_RE = re.compile(r"(?i)(?:\bv|\bver(?:sion)?\s*[=:]?\s*)$")

# A JWT segment is base64 of a JSON claim set. Decoding the bearer token off a
# curl command line yields claim text, and claim text is full of hostnames.
_B64URL_TAIL_RE = re.compile(r"[A-Za-z0-9+/=_-]{8,}$")
_B64URL_HEAD_RE = re.compile(r"[A-Za-z0-9+/=_-]{8,}")

# Without a TLD check, Net.WebClient and every filename become a "domain" bound
# for a rate-limited intel API. Small on purpose: what Windows telemetry shows,
# plus the TLDs favoured for throwaway infrastructure.
_KNOWN_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "co",
    "ai", "app", "dev", "cloud", "online", "site", "shop", "store", "click",
    "link", "live", "life", "world", "space", "website", "digital", "tech",
    "xyz", "top", "icu", "cc", "tk", "ml", "ga", "cf", "gq", "su", "ru", "cn",
    "pw", "buzz", "monster", "rest", "fit", "wang", "work", "party", "stream",
    "download", "loan", "men", "review", "science", "date", "racing", "win",
    "de", "nl", "fr", "uk", "it", "es", "pl", "se", "no", "fi", "dk", "ch",
    "at", "be", "cz", "ro", "gr", "pt", "hu", "ua", "tr", "il", "ir", "in",
    "jp", "kr", "hk", "sg", "au", "nz", "ca", "us", "br", "mx", "ar", "za",
    "eu", "me", "tv", "cx", "ws", "to", "gg", "sh", "is", "lv", "lt", "ee",
}

# Telemetry is full of "bash install.sh", so a candidate ending in one of these
# counts only where the surrounding text puts it on a network.
_EXTENSION_TLDS = {"sh", "pl", "cc"}
_NETWORK_PREFIXES = ("://", "//", "\\\\", "@")


# Field names that carry direction. Anything unlisted is a destination, which is
# the right default for command lines and paths.
_SOURCE_FIELDS = {
    "sourceip", "source_ip", "sourceaddress", "src", "srcip", "ipaddress",
    "clientip", "clientaddress", "remoteip", "remoteaddress", "origin", "originip",
}
_ASSET_FIELDS = {
    "host", "hostname", "computer", "computername", "asset", "device", "machine",
}
# Bookkeeping fields, scanned for nothing. "source" here is the log channel
# (PS4104 / SECURITY / SYSMON); the network origin lives in _SOURCE_FIELDS.
_SKIP_FIELDS = {
    "why", "rule", "ruleid", "attack", "severity", "time", "source", "logsource",
    "logontype", "id",
}


def field_role(name):
    """Map a finding's field name to the direction its indicators point."""
    lowered = str(name).lower().replace("-", "_")
    if lowered in _ASSET_FIELDS:
        return "asset"
    if lowered in _SOURCE_FIELDS:
        return "source"
    return "destination"


def _valid_ip(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


# Explicit rather than ipaddress.is_private, which also covers the documentation
# and benchmark ranges. CGNAT (100.64.0.0/10) is carrier space, so it stays out.
_INTERNAL_NETS = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "fc00::/7",  # the IPv6 unique-local range, the v6 equivalent of the LAN
    )
]


def _ip_scope(addr):
    """Classify an IP so the scorer can tell 'talks to the internet' from 'talks to a DC'."""
    if addr.is_loopback:
        return "loopback"
    # Link-local is its own scope, never "internal": 169.254.169.254 is the cloud
    # instance-metadata service, and reaching it is credential theft (T1552.005).
    if addr.is_link_local:
        return "link_local"
    if any(addr in net for net in _INTERNAL_NETS):
        return "internal"
    if addr.is_multicast or addr.is_unspecified:
        return "reserved"
    return "external"


def _domain_scope(value, internal_suffixes):
    """Internal FQDNs are the DNS half of the LAN; without this they score as external."""
    if not internal_suffixes:
        return "external"
    lowered = value.lower().rstrip(".")
    for suffix in internal_suffixes:
        suffix = str(suffix).lower().strip().rstrip(".")
        if not suffix:
            continue
        bare = suffix.lstrip(".")
        if lowered == bare or lowered.endswith("." + bare):
            return "internal"
    return "external"


def _looks_like_token(text, start, end):
    """True when a Base64 run is a bearer-token segment rather than a payload."""
    if text[start:start + 3] == "eyJ":  # base64 of '{"' - a JSON claim set
        return True
    before, after = text[:start], text[end:]
    if before.endswith(".") and _B64URL_TAIL_RE.search(before[:-1]):
        return True
    if after.startswith(".") and _B64URL_HEAD_RE.match(after[1:]):
        return True
    return False


def _decode_candidates(text):
    """Yield plausible plaintext recovered from Base64 blobs inside `text`."""
    text = text or ""
    for match in _B64_RE.finditer(text):
        if _looks_like_token(text, match.start(), match.end()):
            continue
        blob = match.group()
        # PowerShell -enc requires a length that is a multiple of 4 after padding.
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        for encoding in ("utf-16-le", "utf-8"):
            try:
                decoded = raw.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
            # Reject binary noise: real commands are mostly printable ASCII.
            printable = sum(1 for ch in decoded if 32 <= ord(ch) < 127 or ch in "\r\n\t")
            if decoded and printable / len(decoded) > 0.85:
                yield decoded
                break


def _on_a_network(text, start):
    before = text[:start]
    return any(before.endswith(prefix) for prefix in _NETWORK_PREFIXES)


def _scan(text, via_decode, sink, role, internal_suffixes=None):
    if not text:
        return

    for match in _URL_RE.findall(text):
        sink(("url", match.rstrip(".,);"), via_decode, role))

    for match in _IPV4_RE.finditer(text):
        if _VERSION_CONTEXT_RE.search(text[max(0, match.start() - 12):match.start()]):
            continue
        addr = _valid_ip(match.group())
        if addr is not None:
            sink(("ip", str(addr), via_decode, role), scope=_ip_scope(addr))

    for match in _DOMAIN_RE.finditer(text):
        candidate = match.group(1)
        tld = candidate.rsplit(".", 1)[-1].lower()
        if tld not in _KNOWN_TLDS:
            continue
        if tld in _EXTENSION_TLDS and not _on_a_network(text, match.start(1)):
            continue
        if _valid_ip(candidate) is not None:
            continue  # an IP already captured above
        value = candidate.lower()
        sink(("domain", value, via_decode, role),
             scope=_domain_scope(value, internal_suffixes))

    for candidate in _HASH_RE.findall(text):
        sink(("hash", candidate.lower(), via_decode, role))


# Elastic and Splunk exports nest the interesting string a level or two down
# ({"CommandLine": {"raw": "..."}}). The cap stops a crafted document recursing.
_MAX_FIELD_DEPTH = 4


def _iter_strings(value, depth=_MAX_FIELD_DEPTH):
    if isinstance(value, str):
        yield value
        return
    if depth <= 0:
        return
    if isinstance(value, dict):
        children = value.values()
    elif isinstance(value, (list, tuple)):
        children = value
    else:
        return  # numbers, booleans and None carry no indicators
    for child in children:
        for text in _iter_strings(child, depth - 1):
            yield text


def _fields(finding):
    """The (role, text) pairs worth scanning. Tolerates a non-dict finding."""
    if not isinstance(finding, dict):
        return
    for field, value in finding.items():
        if str(field).lower() in _SKIP_FIELDS:
            continue
        role = field_role(field)
        for text in _iter_strings(value):
            yield role, text


def extract(finding, internal_domain_suffixes=None):
    """Return the deduplicated list of IOCs referenced by one finding.

    Each IOC is a dict: {type, value, role, via_decode, scope?}. Role is part of
    the identity, since one host can both receive a connection and make one.

    `internal_domain_suffixes` is the estate's own DNS suffixes (".corp.com").
    Without it every FQDN scopes external and a file server reads as internet
    infrastructure.
    """
    collected = {}

    def sink(key, **extra):
        ioc_type, value, via_decode, role = key
        identity = (ioc_type, value, role)
        existing = collected.get(identity)
        if existing is None:
            collected[identity] = {
                "type": ioc_type,
                "value": value,
                "role": role,
                "via_decode": via_decode,
                **extra,
            }
        elif not via_decode:
            # Seen in cleartext as well, which is the more useful framing.
            existing["via_decode"] = False

    for role, value in _fields(finding):
        if role in ("source", "asset"):
            # Parsed whole, or a bracketed or zone-tagged IPv6 origin is missed
            # and the logon scores as if it came from the local console.
            literal = value.strip().strip("[]").split("%")[0]
            addr = _valid_ip(literal)
            if addr is not None:
                sink(("ip", str(addr), False, role), scope=_ip_scope(addr))
                continue
        _scan(value, False, sink, role, internal_domain_suffixes)
        if role == "destination":
            # Only command-line style fields carry encoded payloads. Decoding a
            # source or asset address would invent indicators out of its bytes.
            for decoded in _decode_candidates(value):
                _scan(decoded, True, sink, role, internal_domain_suffixes)

    role_order = {"source": 0, "destination": 1, "asset": 2}
    type_order = {"url": 0, "ip": 1, "domain": 2, "hash": 3}
    return sorted(
        collected.values(),
        key=lambda i: (role_order[i["role"]], type_order[i["type"]], i["value"]),
    )


def decoded_commands(finding):
    """Human-readable plaintext recovered from encoded fields, for the report."""
    out = []
    for role, value in _fields(finding):
        if role != "destination":
            continue
        for decoded in _decode_candidates(value):
            text = decoded.strip()
            if text and text not in out:
                out.append(text)
    return out
