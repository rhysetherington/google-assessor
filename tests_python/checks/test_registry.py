"""The registry is what makes one check easy to find and redo. These tests keep it honest: every check in the mapping has exactly
one function, in the domain module that owns it, with a docstring an auditor can read; and running one check really runs only that check."""

import io
import unittest
from contextlib import redirect_stdout

from gcp_gap_assessment.__main__ import main
from gcp_gap_assessment.assess import CHECK_INDEX, DOMAINS, resolve_checks, run_assessment
from gcp_gap_assessment.checks.common import Context
from gcp_gap_assessment.model import CONTROL_MAPPING, Options
from tests_python.fakes import PROJECT, FakeGcloud, add_binding, healthy

PREFIX = {"Iam": "IAM", "Audit": "LOG", "Network": "NET", "Compute": "CMP", "Storage": "STO", "Sql": "SQL", "Kms": "KMS", "OrgPolicy": "ORG"}


class Registry(unittest.TestCase):
    def test_every_mapped_check_has_exactly_one_function(self):
        registered = [c.id for module in DOMAINS.values() for c in module.CHECKS]
        self.assertEqual(sorted(set(registered)), sorted(registered), "a check id is registered twice")
        self.assertEqual(set(CONTROL_MAPPING), set(registered), "mapping and registry disagree")

    def test_each_domain_module_owns_one_id_prefix(self):
        for domain, module in DOMAINS.items():
            with self.subTest(domain):
                self.assertEqual(1, len({c.id.split("-")[0] for c in module.CHECKS}))

    def test_each_check_function_is_documented(self):
        for domain, module in DOMAINS.items():
            for c in module.CHECKS:
                with self.subTest(c.id):
                    self.assertTrue((c.run.__doc__ or "").strip(), f"{c.id} ({domain}) needs a docstring saying what it checks")

    def test_mapping_domain_names_match_the_module(self):
        names = {"Iam": "Identity and IAM", "Logging": "Logging and monitoring", "Network": "Networking", "Compute": "Compute Engine",
                 "Storage": "Cloud Storage", "Sql": "Cloud SQL", "Kms": "Cloud KMS", "OrgPolicy": "Organization policy"}
        for cid, domain in CHECK_INDEX.items():
            with self.subTest(cid):
                self.assertEqual(names[domain], CONTROL_MAPPING[cid]["domain"])


class RedoOneCheck(unittest.TestCase):
    def test_only_runs_just_that_check_and_reads_less(self):
        full_g, one_g = FakeGcloud(healthy()), FakeGcloud(healthy())
        from gcp_gap_assessment.checks import compute
        full = compute.collect(Context(full_g, Options()), [PROJECT])
        one = compute.collect(Context(one_g, Options()), [PROJECT], only={"CMP-006"})
        self.assertEqual(["CMP-006"], [f["FindingId"] for f in one])
        self.assertEqual(8, len(full))
        self.assertLess(len(one_g.calls), len(full_g.calls))  # CMP-006 needs only the instance list, not the project metadata

    def test_a_failure_in_one_check_does_not_take_its_neighbours_with_it(self):
        from gcp_gap_assessment.checks import storage
        fx = healthy()
        from tests_python.fakes import DENIED
        fx["storage buckets get-iam-policy gs://data-bucket"] = DENIED
        by_id = {f["FindingId"]: f for f in storage.collect(Context(FakeGcloud(fx), Options()), [PROJECT])}
        self.assertEqual("NotAssessed", by_id["STO-001"]["Status"])
        self.assertEqual("Pass", by_id["STO-002"]["Status"])

    def test_run_assessment_with_check_ids_runs_only_those(self):
        a = run_assessment(FakeGcloud(healthy()), [PROJECT], check_ids=["iam-003", "CMP-005"], no_prompt=True)
        self.assertEqual(["CMP-005", "IAM-003"], sorted(f["FindingId"] for f in a["Findings"]))
        self.assertEqual(["CMP-005", "IAM-003"], a["OnlyChecks"])
        self.assertEqual(2, a["Summary"]["TotalChecks"])

    def test_an_opt_in_domain_runs_when_one_of_its_checks_is_requested(self):
        a = run_assessment(FakeGcloud(healthy()), [PROJECT], check_ids=["KMS-002"], no_prompt=True)
        self.assertEqual(["KMS-002"], [f["FindingId"] for f in a["Findings"]])

    def test_the_redone_check_still_finds_the_gap(self):
        fx = healthy()
        add_binding(fx, "roles/viewer", "allUsers")
        a = run_assessment(FakeGcloud(fx), [PROJECT], check_ids=["IAM-003"], no_prompt=True)
        self.assertEqual("Gap", a["Findings"][0]["Status"])

    def test_unknown_ids_are_rejected_with_a_hint(self):
        with self.assertRaisesRegex(ValueError, "IAM-999.*--list-checks"):
            resolve_checks(["IAM-003", "IAM-999"])

    def test_partial_runs_are_labelled_in_the_reports(self):
        from gcp_gap_assessment import report
        a = run_assessment(FakeGcloud(healthy()), [PROJECT], check_ids=["IAM-003"], no_prompt=True)
        self.assertIn("PARTIAL ASSESSMENT", report.to_markdown(a))
        self.assertIn("PARTIAL ASSESSMENT", report.to_html(a))
        full = run_assessment(FakeGcloud(healthy()), [PROJECT], no_prompt=True)
        self.assertNotIn("PARTIAL", report.to_markdown(full))


class Cli(unittest.TestCase):
    def test_list_checks_needs_no_gcloud(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(0, main(["--list-checks"], gcloud=None))
        lines = out.getvalue().strip().splitlines()
        self.assertEqual(47, len(lines))
        self.assertTrue(any(line.startswith("IAM-003  Iam") for line in lines))

    def test_check_flag_redoes_one_check_from_the_command_line(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d, redirect_stdout(io.StringIO()) as out:
            code = main(["--project-id", PROJECT, "--check", "NET-001", "--no-prompt", "--client-name", "Redo", "--assessment-date", "2026-10-18",
                         "--export-path", d], gcloud=FakeGcloud(healthy()))
            self.assertEqual(0, code)
            self.assertIn("1 checks", out.getvalue())
            self.assertIn("PARTIAL ASSESSMENT", (Path(d) / "Redo-2026-10-18" / "Redo-2026-10-18-Assessment.md").read_text())


if __name__ == "__main__":
    unittest.main()
