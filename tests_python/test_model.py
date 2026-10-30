"""Aggregation of many projects into one finding, failure containment, scoring, validators, accepted risks, the guard."""

import unittest
from datetime import date

from google_gap_assessment import accepted
from google_gap_assessment.cloud import guard
from google_gap_assessment.cloud.checks import network
from google_gap_assessment.cloud.checks.common import Context, service_account_kind
from google_gap_assessment.cloud.checks.orgpolicy import policy_enforced
from google_gap_assessment.cloud.gcloud import GcloudError
from google_gap_assessment.model import ProjectResult as R, measure_score, merge_results, new_finding, run_project_check
from google_gap_assessment.validation import is_numeric_id, is_project_id, is_service_account_email, safe_name
from tests_python.fakes import DENIED, FakeGcloud, add_binding, healthy


class Merge(unittest.TestCase):
    def test_gap_lists_affected_objects_of_every_project(self):
        f = merge_results("NET-001", [R("a", "NET-001", "Gap", ["a/default"]), R("b", "NET-001", "Pass"), R("c", "NET-001", "Gap", ["c/default"])])
        self.assertEqual("Gap", f["Status"])
        self.assertEqual(2, f["AffectedCount"])
        self.assertIn("c/default", f["AffectedObjects"])

    def test_gap_survives_an_unreadable_project_and_names_it(self):
        f = merge_results("NET-001", [R("a", "NET-001", "Gap", ["a/default"]), R("b-proj", "NET-001", "NotAssessed", [], "denied")])
        self.assertEqual("Gap", f["Status"])
        self.assertIn("b-proj", f["Detail"])

    def test_never_a_pass_when_nothing_could_be_read(self):
        f = merge_results("NET-001", [R("a", "NET-001", "NotAssessed", [], "x"), R("b", "NET-001", "NotAssessed", [], "x")])
        self.assertEqual("NotAssessed", f["Status"])

    def test_all_pass_is_pass_and_no_results_is_not_assessed(self):
        self.assertEqual("Pass", merge_results("NET-001", [R("a", "NET-001", "Pass")])["Status"])
        self.assertEqual("NotAssessed", merge_results("NET-001", [])["Status"])

    def test_projects_where_the_service_is_off_are_named(self):
        f = merge_results("NET-001", [R("a", "NET-001", "Pass"), R("b-proj", "NET-001", "NotApplicable", [], "off")])
        self.assertIn("b-proj", f["Detail"])


class ProjectCheck(unittest.TestCase):
    def test_exception_becomes_not_assessed_for_every_id(self):
        def boom(_p): raise RuntimeError("boom")
        r = run_project_check("a", ["X-1", "X-2"], boom)
        self.assertEqual(["NotAssessed", "NotAssessed"], [x.status for x in r])

    def test_disabled_api_is_not_applicable(self):
        def off(_p): raise GcloudError("SERVICE_DISABLED", "ApiDisabled")
        self.assertEqual("NotApplicable", run_project_check("a", ["X-1"], off)[0].status)

    def test_disabled_api_is_not_assessed_when_it_says_nothing_about_the_target(self):
        def off(_p): raise GcloudError("SERVICE_DISABLED", "ApiDisabled")
        r = run_project_check("a", ["X-1"], off, disabled_api_means_unused=False)[0]
        self.assertEqual("NotAssessed", r.status)
        self.assertIn("Enable", r.detail)

    def test_results_before_a_failure_are_discarded(self):
        def partial(p):
            yield R(p, "X-1", "Pass")
            raise RuntimeError("later")
        r = run_project_check("a", ["X-1", "X-2"], partial)
        self.assertFalse(any(x.status == "Pass" for x in r))
        self.assertEqual(2, len(r))

    def test_a_forgotten_id_is_not_assessed_never_a_pass(self):
        r = run_project_check("a", ["X-1", "X-2"], lambda p: [R(p, "X-1", "Pass")])
        self.assertEqual("NotAssessed", next(x for x in r if x.id == "X-2").status)

    def test_several_projects_through_a_real_collector(self):
        fx = healthy()
        gcloud = FakeGcloud(fx)
        for p in ("proj-a-0001", "proj-b-0002", "proj-c-0003"):
            for k in ("compute firewall-rules list", "compute networks subnets list", "dns managed-zones list"):
                fx[f"{p}::{k}"] = fx[k]
        fx["proj-a-0001::compute networks list"] = [{"name": "default"}]
        fx["proj-b-0002::compute networks list"] = DENIED
        fx["proj-c-0003::compute networks list"] = [{"name": "vpc-main"}]
        f = next(x for x in network.collect(Context(gcloud), ["proj-a-0001", "proj-b-0002", "proj-c-0003"]) if x["FindingId"] == "NET-001")
        self.assertEqual("Gap", f["Status"])
        self.assertEqual(["proj-a-0001/default"], f["AffectedObjects"])
        self.assertIn("proj-b-0002", f["Detail"])


class Scoring(unittest.TestCase):
    def test_weights_by_severity_and_counts_not_assessed_against_you(self):
        f = [{"Severity": "Critical", "Status": "Pass"}, {"Severity": "High", "Status": "Gap"},
             {"Severity": "Medium", "Status": "NotAssessed"}, {"Severity": "Low", "Status": "Accepted"}]
        self.assertEqual(57.9, measure_score(f))  # (10 + 1) / (10 + 5 + 3 + 1)

    def test_none_when_nothing_to_score(self):
        self.assertIsNone(measure_score([]))


class Validation(unittest.TestCase):
    def test_project_ids(self):
        for ok in ("my-project-123", "abcdef", "example.com:my-project", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"):
            self.assertTrue(is_project_id(ok), ok)
        for bad in ("", "short", "UPPER-case-1", "1starts-with-digit", "ends-with-dash-", "has space in-it", "x;rm -rf /", "--flag=injected",
                    "../../etc/passwd", "a$(whoami)bcdef", "this-id-is-far-too-long-for-a-project", "valid-project-1\n"):
            self.assertFalse(is_project_id(bad), repr(bad))

    def test_other_identifiers(self):
        self.assertTrue(is_numeric_id("123456789012"))
        for bad in ("12", "123abc456", "123;456", "123\n"):
            self.assertFalse(is_numeric_id(bad), bad)
        self.assertTrue(is_service_account_email("assessor@sec-project.iam.gserviceaccount.com"))
        for bad in ("someone@contoso.com", "x@y.iam.gserviceaccount.com", "a@b.iam.gserviceaccount.com --flag"):
            self.assertFalse(is_service_account_email(bad), bad)

    def test_safe_name_cannot_add_path_separators(self):
        self.assertNotRegex(safe_name("../../etc/passwd"), r"[/\\.]")
        self.assertEqual("Contoso-Ltd", safe_name("Contoso Ltd."))
        self.assertEqual("Assessment", safe_name(""))


class Classification(unittest.TestCase):
    def test_service_account_kinds(self):
        table = {
            "123456789012-compute@developer.gserviceaccount.com": "DefaultCompute",
            "my-project-123@appspot.gserviceaccount.com": "DefaultAppEngine",
            "123456789012@cloudservices.gserviceaccount.com": "GoogleManaged",
            "123456789012@cloudbuild.gserviceaccount.com": "GoogleManaged",
            "service-123456789012@gcp-sa-pubsub.iam.gserviceaccount.com": "GoogleManaged",
            "service-123456789012@compute-system.iam.gserviceaccount.com": "GoogleManaged",
            "service-123456789012@container-engine-robot.iam.gserviceaccount.com": "GoogleManaged",
            "deployer@my-project-123.iam.gserviceaccount.com": "UserManaged",
            "person@contoso.com": "Other",
        }
        for email, kind in table.items():
            with self.subTest(email):
                self.assertEqual(kind, service_account_kind(email))

    def test_org_policy_parsing(self):
        rule = lambda **k: {"spec": {"rules": [k]}}  # noqa: E731
        self.assertTrue(policy_enforced(rule(enforce=True), "boolean"))
        self.assertFalse(policy_enforced(rule(enforce=False), "boolean"))
        self.assertFalse(policy_enforced(None, "boolean"))
        self.assertFalse(policy_enforced(rule(enforce=True, condition={"expression": "x"}), "boolean"))
        self.assertTrue(policy_enforced(rule(denyAll=True), "deny_all"))
        self.assertFalse(policy_enforced(rule(allowAll=True), "deny_all"))
        self.assertTrue(policy_enforced(rule(values={"allowedValues": ["C01"]}), "allow_list"))
        self.assertFalse(policy_enforced(rule(allowAll=True), "allow_list"))


class AcceptedRisks(unittest.TestCase):
    def gap(self, *affected):
        return new_finding("NET-001", "Gap", list(affected))

    def test_whole_finding_accepted_and_expiry(self):
        f = self.gap("a/default")
        accepted.apply([f], [{"findingId": "NET-001", "reason": "legacy", "approvedBy": "J", "expires": "2999-01-01"}])
        self.assertEqual("Accepted", f["Status"])
        self.assertEqual("legacy", f["AcceptedRisk"]["Reason"])
        g = self.gap("a/default")
        accepted.apply([g], [{"findingId": "NET-001", "reason": "legacy", "expires": "2000-01-01"}])
        self.assertEqual("Gap", g["Status"])

    def test_old_acceptance_cannot_hide_a_new_object(self):
        f = self.gap("a/default", "b/default")
        accepted.apply([f], [{"findingId": "NET-001", "reason": "legacy", "affected": ["a/default"]}])
        self.assertEqual("Gap", f["Status"])

    def test_covers_uses_prefix_match(self):
        f = self.gap("a/default (detail that changes)")
        self.assertTrue(accepted.covers(f, {"findingId": "NET-001", "reason": "r", "affected": ["a/default"]}, date(2026, 1, 1)))


class ElevatedGuard(unittest.TestCase):
    def setUp(self):
        fx = healthy()
        add_binding(fx, "roles/owner", "user:assessor@contoso.com")
        self.g = FakeGcloud(fx)

    def test_finds_owner_held_directly(self):
        self.assertEqual([("test-project-one", "roles/owner")], guard.elevated_assignments(self.g, "assessor@contoso.com", ["test-project-one"]))
        self.assertEqual([], guard.elevated_assignments(self.g, "someone.else@contoso.com", ["test-project-one"]))

    def test_declining_stops_the_run(self):
        with self.assertRaisesRegex(RuntimeError, "Cancelled"):
            guard.confirm_elevated_use(self.g, "assessor@contoso.com", ["test-project-one"], ask=lambda _p: "n", interactive=True)

    def test_agreeing_continues(self):
        guard.confirm_elevated_use(self.g, "assessor@contoso.com", ["test-project-one"], ask=lambda _p: "y", interactive=True)

    def test_allow_flag_continues_without_asking(self):
        def never(_p): raise AssertionError("must not ask")
        guard.confirm_elevated_use(self.g, "assessor@contoso.com", ["test-project-one"], allow=True, ask=never, interactive=True)

    def test_non_interactive_run_is_refused_unless_allowed(self):
        with self.assertRaisesRegex(RuntimeError, "allow-elevated-account"):
            guard.confirm_elevated_use(self.g, "assessor@contoso.com", ["test-project-one"], interactive=False)

    def test_read_only_account_is_silent(self):
        def never(_p): raise AssertionError("must not ask")
        guard.confirm_elevated_use(self.g, "reader@contoso.com", ["test-project-one"], ask=never, interactive=True)


if __name__ == "__main__":
    unittest.main()


class ReportDefaults(unittest.TestCase):
    def test_every_run_writes_json_markdown_and_html_unless_told_otherwise(self):
        from google_gap_assessment.__main__ import build_parser
        self.assertEqual(["JSON", "Markdown", "HTML"], build_parser().parse_args([]).format)

    def test_default_assessment_name_follows_what_was_assessed(self):
        from google_gap_assessment.metadata import DEFAULT_NAMES
        self.assertIn("Workspace", DEFAULT_NAMES["workspace"])
        self.assertNotIn("Workspace", DEFAULT_NAMES["cloud"])


class HtmlReport(unittest.TestCase):
    def test_not_assessed_reasons_are_grouped_and_the_lead_in_is_dropped(self):
        from google_gap_assessment.report import _not_assessed_groups
        same = "Could not be assessed in 1 project(s): t.example (DNS lookups were switched off (--no-dns), so this was not checked.)"
        groups = _not_assessed_groups([{"Detail": same}, {"Detail": same}, {"Detail": "HTTP 403 denied"}])
        self.assertEqual([2, 1], [len(items) for _, items in groups])
        self.assertEqual("DNS lookups were switched off (--no-dns), so this was not checked.", groups[0][0])

    def test_the_report_is_self_contained(self):
        import re
        from google_gap_assessment import report
        from tests_python.workspace.ws_fakes import Tenant
        from google_gap_assessment.assess import run_assessment
        html = report.to_html(run_assessment(workspace=Tenant().session(), no_prompt=True))
        self.assertIsNone(re.search(r'(?:src|href)="https?://', html))  # no fonts, scripts or images fetched from anywhere


class HtmlBranding(unittest.TestCase):
    def _assessment(self):
        from google_gap_assessment.assess import run_assessment
        from tests_python.workspace.ws_fakes import Tenant
        t = Tenant(); t.settings["gmail.auto_forwarding"] = {"enableAutoForwarding": True}
        return run_assessment(workspace=t.session(), no_prompt=True, client_name="Acme")

    def test_logo_is_embedded_as_a_data_uri_and_a_bad_one_is_refused(self):
        import tempfile
        from pathlib import Path
        from google_gap_assessment import report
        with tempfile.TemporaryDirectory() as d:
            good = Path(d, "logo.svg"); good.write_text("<svg xmlns='http://www.w3.org/2000/svg'/>")
            uri = report.logo_data_uri(str(good))
            self.assertTrue(uri.startswith("data:image/svg+xml;base64,"))
            self.assertIn('class="logo-wrap"', report.to_html(self._assessment(), logo=uri))
            self.assertNotIn('class="logo-wrap"', report.to_html(self._assessment()))
            for name, size in (("notes.txt", 10), ("big.png", 500_000)):
                Path(d, name).write_bytes(b"x" * size)
                with self.assertRaises(ValueError):
                    report.logo_data_uri(str(Path(d, name)))
            with self.assertRaises(ValueError):
                report.logo_data_uri(str(Path(d, "missing.png")))

    def test_a_logo_that_is_not_a_data_uri_is_never_rendered(self):
        from google_gap_assessment import report
        html = report.to_html(self._assessment(), logo='javascript:alert(1)"><script>alert(1)</script>')
        self.assertNotIn('class="logo-wrap"', html)
        self.assertNotIn("<script>alert", html)

    def test_executive_summary_states_the_numbers_and_the_top_risks(self):
        from google_gap_assessment import report
        a = self._assessment()
        html = report.to_html(a)
        self.assertIn(f"<b>{a['Summary']['TotalChecks']}</b> read-only checks", html)
        self.assertIn("Fix these first:", html)

    def test_every_gap_area_has_an_anchor_the_heat_map_can_link_to(self):
        import re
        from google_gap_assessment import report
        html = report.to_html(self._assessment())
        for target in re.findall(r'class="tile" href="#(a-\d+)"', html):
            self.assertIn(f'id="{target}"', html)


class Comparison(unittest.TestCase):
    @staticmethod
    def _f(fid, status, affected=0, sev="High"):
        return {"FindingId": fid, "Name": f"Check {fid}", "Severity": sev, "Status": status, "AffectedCount": affected, "Detail": ""}

    def _a(self, findings, score):
        passed = sum(1 for f in findings if f["Status"] == "Pass")
        return {"Findings": findings, "Score": score, "Metadata": {"ClientName": "Acme", "AssessmentDate": "2026-10-25"},
                "AssessedAt": "2026-10-25T10:00:00+00:00",
                "Summary": {"Passed": passed, "Gaps": sum(1 for f in findings if f["Status"] == "Gap"),
                            "NotAssessed": sum(1 for f in findings if f["Status"] == "NotAssessed")}}

    def test_every_kind_of_change_is_classified(self):
        from google_gap_assessment.compare import classify
        f = self._f
        cases = [(f("A", "Gap"), f("A", "Pass"), "fixed"), (f("A", "Pass"), f("A", "Gap"), "regressed"),
                 (f("A", "NotAssessed"), f("A", "Pass"), "now_assessed"), (f("A", "Gap"), f("A", "NotAssessed"), "lost"),
                 (f("A", "Gap", 5), f("A", "Gap", 2), "improved"), (f("A", "Gap", 2), f("A", "Gap", 5), "worsened"),
                 (f("A", "Gap", 3), f("A", "Gap", 3), "open"), (f("A", "Pass"), f("A", "Pass"), "same"),
                 (f("A", "NotAssessed"), f("A", "NotAssessed"), "same"), (None, f("A", "Gap"), "added"), (f("A", "Gap"), None, "removed"),
                 (f("A", "Gap"), f("A", "Accepted"), "fixed")]
        for old, new, want in cases:
            self.assertEqual(want, classify(old, new), (old, new))

    def test_page_shows_both_scores_the_delta_and_escapes_names(self):
        from google_gap_assessment import compare
        before = self._a([self._f("A", "Gap"), self._f("B", "Pass")], 40.0)
        evil = self._f("B", "Gap"); evil["Name"] = "<img src=x onerror=alert(1)>"
        after = self._a([self._f("A", "Pass"), evil], 55.5)
        html = compare.to_html(before, after)
        self.assertIn("+15.5 pts", html)
        self.assertIn("Got worse", html)
        self.assertIn("&lt;img src=x", html)
        self.assertNotIn("<img src=x", html)

    def test_cli_refuses_a_file_that_is_not_an_assessment(self):
        import io, tempfile
        from contextlib import redirect_stderr
        from pathlib import Path
        from google_gap_assessment import compare
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d, "x.json"); bad.write_text('{"hello": 1}')
            with redirect_stderr(io.StringIO()) as err:
                self.assertEqual(1, compare.main([str(bad), str(bad)]))
            self.assertIn("not an assessment Findings file", err.getvalue())


class CompareCommand(unittest.TestCase):
    """The second command: choose a saved assessment to start from and compare it with a later one."""

    def setUp(self):
        import json, tempfile
        from pathlib import Path
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for folder, at, score in (("Acme-old", "2026-10-01T10:00:00+00:00", 30.0), ("Acme-mid", "2026-10-10T10:00:00+00:00", 50.0), ("Acme-new", "2026-10-20T10:00:00+00:00", 70.0)):
            (self.root / folder).mkdir()
            (self.root / folder / f"{folder}-Findings.json").write_text(json.dumps({
                "Findings": [{"FindingId": "A", "Name": "Check A", "Severity": "High", "Status": "Gap" if score < 60 else "Pass", "AffectedCount": 1, "Detail": ""}],
                "Score": score, "AssessedAt": at, "Metadata": {"ClientName": "Acme", "AssessmentDate": at[:10]},
                "Scope": {"Workspace": {"PrimaryDomain": "acme.example"}}, "Summary": {"Passed": 0, "Gaps": 1, "NotAssessed": 0, "TotalChecks": 1}}))
        (self.root / "junk").mkdir(); (self.root / "junk" / "junk-Findings.json").write_text("not json")

    def _run(self, argv, answers=(), interactive=True):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from google_gap_assessment import compare
        it = iter(answers)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = compare.main(argv + ["--root", str(self.root)], ask=lambda _p: next(it), interactive=interactive)
        return code, out.getvalue(), err.getvalue()

    def test_saved_assessments_are_found_newest_first_and_junk_is_skipped(self):
        from google_gap_assessment import compare
        self.assertEqual(["Acme-new", "Acme-mid", "Acme-old"], [r["folder"] for r in compare.discover(self.root)])

    def test_the_assessor_picks_the_start_and_the_newest_is_the_default_comparison(self):
        code, out, _ = self._run([], ["3", ""])  # 3 = the oldest in a newest-first list; Enter accepts the default
        self.assertEqual(0, code)
        self.assertIn("30.0% -> 70.0%", out)
        self.assertTrue((self.root / "Acme-new" / "Acme-new-Comparison-from-Acme-old.html").exists())

    def test_the_assessor_can_pick_a_different_assessment_to_compare_with(self):
        code, out, _ = self._run([], ["3", "2"])  # later list is [new, mid]; 2 = mid
        self.assertEqual(0, code)
        self.assertIn("30.0% -> 50.0%", out)

    def test_starting_from_the_newest_is_refused_because_nothing_is_later(self):
        code, _, err = self._run([], ["1"])
        self.assertEqual(1, code)
        self.assertIn("most recent", err)

    def test_two_given_assessments_are_compared_with_the_earlier_on_the_left_even_if_given_backwards(self):
        code, out, _ = self._run([str(self.root / "Acme-new"), str(self.root / "Acme-old")], interactive=False)
        self.assertEqual(0, code)
        self.assertIn("swapped", out)
        self.assertIn("30.0% -> 70.0%", out)

    def test_without_arguments_and_without_a_terminal_it_says_what_to_do(self):
        code, _, err = self._run([], interactive=False)
        self.assertEqual(1, code)
        self.assertIn("BEFORE AFTER", err)

    def test_one_given_assessment_is_compared_with_the_most_recent(self):
        code, out, _ = self._run([str(self.root / "Acme-mid")], interactive=False)
        self.assertEqual(0, code)
        self.assertIn("50.0% -> 70.0%", out)

    def test_the_same_assessment_twice_is_refused(self):
        code, _, err = self._run([str(self.root / "Acme-mid"), str(self.root / "Acme-mid")], interactive=False)
        self.assertEqual(1, code)
        self.assertIn("same assessment", err)

    def test_the_main_command_routes_compare_and_still_treats_a_bare_run_as_assess(self):
        import io
        from contextlib import redirect_stdout
        from google_gap_assessment.__main__ import main
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(0, main(["compare", "--list", "--root", str(self.root)]))
        self.assertIn("Acme-new", out.getvalue())
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(0, main(["assess", "--list-checks"]))
        self.assertIn("GID-001", out.getvalue())
