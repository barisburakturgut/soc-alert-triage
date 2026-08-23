# Sample data

Everything in this folder is **synthetic**. It exists so that `git clone` → run
gives you a full, realistic triage with no API key and no network access.

- **`findings.json`** — 18 fabricated detection findings across 5 accounts,
  shaped exactly like a `Invoke-ThreatHunt.ps1 -Json` export. No log, host,
  account or command in it came from a real system.
- **`mock-intel.json`** — the offline threat-intelligence snapshot the `offline`
  provider reads. The verdicts in it are written by hand to make the triage
  interesting; they are **not** live intelligence and must never be treated as
  such.

**Addresses.** Every external address in these files is from an
[RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) documentation range —
`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` — so that no real host is
implicated by an invented "malicious" verdict. They still classify as *external*
in the engine, which treats only RFC1918 / unique-local space and the DNS
suffixes named in `config/triage.json` as internal — carrier-grade NAT space
(`100.64.0.0/10`) and link-local addresses are deliberately *not* internal. The
one real address is `8.8.8.8`, Google Public DNS, which is here to demonstrate
the `clean` verdict path — and that verdict is true. The internal addresses
(`10.20.x.x`) are RFC1918, so they name no one either.

**Hashes.** Synthetic values generated for this repo. They match no real sample
and will not resolve on VirusTotal.

Baris Burak Turgut
