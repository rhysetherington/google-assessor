"""A whole run against the fake gcloud: scope, metadata, every domain, scoring, accepted risks and the files that come out,
including hostile resource names to prove reports cannot become markup or spreadsheet formulas."""

import json
import re
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from google_gap_assessment import coverage
from google_gap_assessment.__main__ import main
from google_gap_assessment.assess import export_assessment, run_assessment
from google_gap_assessment.model import CONTROL_MAPPING
from tests_python.fakes import DENIED, PROJECT, Err, FakeGcloud, add_binding, healthy

PKG = Path(__file__).parent.parent / "google_gap_assessment"


def run(mutate=None, **kw):
    fx = healthy()
    if mutate:
        mutate(fx)
    kw.setdefault("no_prompt", True)
    kw.setdefault("project_ids", [PROJECT])
    return run_assessment(FakeGcloud(fx), **kw)


class Run(unittest.TestCase):
    def test_healthy_project_scores_100_and_runs_every_default_domain(self):
        a = run()
        self.assertEqual(0, a["Summary"]["Gaps"])
        self.assertEqual(0, a["Summary"]["NotAssessed"])
        self.assertEqual(100, a["Score"])
        self.assertEqual(45, a["Summary"]["TotalChecks"])
        self.assertEqual([PROJECT], [p["ProjectId"] for p in a["Scope"]["Projects"]])

    def test_kms_is_opt_in(self):
        self.assertEqual(2, len(run(domains=["Kms"])["Findings"]))

    def test_organisation_expands_and_unreadable_projects_are_skipped(self):
        def mutate(fx):
            fx["projects list"] = [{"projectId": PROJECT}, {"projectId": "gone-project-02"}]
            fx["projects describe gone-project-02"] = Err("NotFound", "NOT_FOUND")
            fx[f"projects describe {PROJECT}"] = fx["projects describe"]
            fx["organizations describe 111111111111"] = {"displayName": "contoso.com"}
        a = run(mutate, project_ids=[], organization_id="111111111111")
        self.assertEqual(1, len(a["Scope"]["Projects"]))
        self.assertEqual("contoso", a["Metadata"]["ClientName"])

    def test_fails_clearly_when_no_project_can_be_read(self):
        with self.assertRaisesRegex(RuntimeError, "None of the requested projects"):
            run(lambda fx: fx.__setitem__("projects describe", DENIED))

    def test_rejects_a_bad_project_id_before_anything_runs(self):
        with self.assertRaisesRegex(ValueError, "not a project ID"):
            run(project_ids=["x; rm -rf /"])

    def test_no_active_account_stops_the_run(self):
        with self.assertRaisesRegex(RuntimeError, "no active account"):
            run(lambda fx: fx.__setitem__("auth list --filter=status:ACTIVE", []))

    def test_permission_problem_is_not_assessed_and_lowers_the_score(self):
        a = run(lambda fx: fx.__setitem__("compute firewall-rules list", DENIED))
        self.assertEqual("NotAssessed", next(f for f in a["Findings"] if f["FindingId"] == "NET-003")["Status"])
        self.assertLess(a["Score"], 100)

    def test_accepted_risk_file_is_applied(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "accepted.json"
            path.write_text('{"risks":[{"findingId":"IAM-003","reason":"Public site","approvedBy":"J. Smith"}]}')
            a = run(lambda fx: add_binding(fx, "roles/viewer", "allUsers"), accepted_risk_path=str(path))
        f = next(x for x in a["Findings"] if x["FindingId"] == "IAM-003")
        self.assertEqual("Accepted", f["Status"])
        self.assertEqual("J. Smith", f["AcceptedRisk"]["ApprovedBy"])

    def test_elevated_account_is_refused_non_interactively(self):
        with self.assertRaisesRegex(RuntimeError, "can change resources"):
            run(lambda fx: add_binding(fx, "roles/owner", "user:assessor@contoso.com"))  # stdin is not a terminal under test

    def test_elevated_account_runs_with_the_allow_flag(self):
        a = run(lambda fx: add_binding(fx, "roles/owner", "user:assessor@contoso.com"), allow_elevated=True)
        # The run completes, and the owner grant is itself reported (IAM-001 covers people holding Owner).
        self.assertEqual("Gap", next(f for f in a["Findings"] if f["FindingId"] == "IAM-001")["Status"])


class Reports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()

        def evil(fx):
            add_binding(fx, "roles/viewer", "allUsers", "user:<script>alert(1)</script>@evil.com", 'user:=HYPERLINK("http://evil","x")@evil.com')
            fx["compute firewall-rules list"].append({"name": "<img src=x onerror=alert(1)>", "network": ".../vpc-main", "direction": "INGRESS",
                                                      "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "all"}]})
            fx["compute instances list"][0]["metadata"]["items"].append({"key": "startup-script", "value": "export DB_PASSWORD=hunter2-SECRET"})
            fx["compute project-info describe"]["commonInstanceMetadata"]["items"].append({"key": "ssh-keys", "value": "alice:ssh-rsa AAAASECRETKEY"})
        cls.assessment = run(evil, client_name="Hostile", assessment_date="2026-10-18", options=None)
        cls.files = export_assessment(cls.assessment, Path(cls.tmp.name), ["JSON", "Markdown", "HTML"], include_evidence=True)
        cls.folder = Path(cls.tmp.name) / "Hostile-2026-10-18"

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_folder_and_file_names_are_clientname_date(self):
        self.assertTrue(self.folder.is_dir())
        for name in ("Hostile-2026-10-18-Findings.json", "Hostile-2026-10-18-Assessment.md", "Hostile-2026-10-18-Assessment.html"):
            self.assertTrue((self.folder / name).exists(), name)

    def test_html_encodes_names(self):
        html = (self.folder / "Hostile-2026-10-18-Assessment.html").read_text()
        self.assertNotIn("<script>alert", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;img src=x", html)

    def test_markdown_neutralises_angle_brackets(self):
        md = (self.folder / "Hostile-2026-10-18-Assessment.md").read_text()
        self.assertNotIn("<script>alert", md)
        self.assertNotIn("<img src=x", md)
        self.assertIn("evidence/IAM-003.csv", md)

    def test_evidence_files_are_written_and_formula_values_are_neutralised(self):
        from google_gap_assessment.evidence import safe_csv_value
        self.assertTrue((self.folder / "evidence" / "IAM-003.csv").exists())
        self.assertTrue((self.folder / "evidence" / "_index.csv").exists())
        # Affected items start with the project ID today, so also prove the sanitiser directly: a leading = + - @ or tab is defused.
        for hostile in ('=HYPERLINK("http://evil","x")', "+1+1", "-2+3", "@SUM(A1)", "\tcmd"):
            self.assertTrue(safe_csv_value(hostile).startswith("'"), hostile)
        self.assertEqual("plain text", safe_csv_value("plain text"))
        self.assertEqual("one two", safe_csv_value("one\ntwo"))

    def test_json_is_valid_and_complete(self):
        data = json.loads((self.folder / "Hostile-2026-10-18-Findings.json").read_text())
        self.assertEqual(45, len(data["Findings"]))
        self.assertEqual(PROJECT, data["Scope"]["Projects"][0]["ProjectId"])

    def test_no_raw_metadata_or_secrets_anywhere(self):
        everything = "\n".join(p.read_text() for p in self.folder.rglob("*") if p.is_file())
        self.assertNotRegex(everything, r"hunter2|AAAASECRETKEY")

    @unittest.skipIf(sys.platform.startswith("win"), "POSIX permissions")
    def test_folder_is_restricted_to_the_current_user(self):
        self.assertEqual(0o700, stat.S_IMODE(self.folder.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE((self.folder / "Hostile-2026-10-18-Findings.json").stat().st_mode))


class Mapping(unittest.TestCase):
    def test_every_control_is_complete_sorted_and_used_by_a_collector(self):
        ids = list(CONTROL_MAPPING)
        self.assertEqual(sorted(ids), ids)
        code = "\n".join(p.read_text() for p in list((PKG / "cloud" / "checks").glob("*.py")) + list((PKG / "workspace" / "checks").glob("*.py")))
        for cid, c in CONTROL_MAPPING.items():
            with self.subTest(cid):
                self.assertRegex(cid, r"^(IAM|LOG|NET|CMP|STO|SQL|KMS|ORG|GID)-\d{3}$")
                self.assertIn(c["severity"], ("Critical", "High", "Medium", "Low"))
                self.assertRegex(c["scf"], r"^[A-Z]{3}-\d{2}$")
                self.assertRegex(c["nistCsf"], r"^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$")
                self.assertTrue(c["remediation"] and c["name"] and c["domain"])
                for cis in c["cis"]:
                    self.assertRegex(cis, r"^\d+\.\d+(\.\d+)?$")
                self.assertIn(f'"{cid}"', code, f"{cid} is not produced by any collector")

    def test_every_id_used_in_code_has_a_mapping_entry(self):
        code = "\n".join(p.read_text() for p in list((PKG / "cloud" / "checks").glob("*.py")) + list((PKG / "workspace" / "checks").glob("*.py")))
        used = set(re.findall(r'"((?:IAM|LOG|NET|CMP|STO|SQL|KMS|ORG|GID)-\d{3})"', code))
        self.assertEqual(set(), used - set(CONTROL_MAPPING))


class Docs(unittest.TestCase):
    def test_coverage_page_is_up_to_date(self):
        self.assertEqual(0, coverage.main(["--check"]))

    def test_readme_states_the_real_number_of_checks(self):
        self.assertIn(f"**{len(CONTROL_MAPPING)} checks**", (PKG.parent / "README.md").read_text())

    def test_no_secret_looking_content_in_the_repository(self):
        pattern = re.compile(r"BEGIN (RSA |EC )?PRIVATE KEY|\"private_key\"\s*:|ya29\.[0-9A-Za-z_-]{20,}|AIza[0-9A-Za-z_-]{30,}")
        for path in PKG.parent.rglob("*"):
            if path.is_file() and path.suffix in {".py", ".ps1", ".psm1", ".psd1", ".json", ".yml"} and ".git" not in path.parts and "GcpAssessment" not in path.parts:
                self.assertIsNone(pattern.search(path.read_text(errors="ignore")), str(path))


class Cli(unittest.TestCase):
    def test_cli_runs_end_to_end_and_writes_reports(self):
        with tempfile.TemporaryDirectory() as d:
            code = main(["--project-id", PROJECT, "--no-prompt", "--export-path", d, "--client-name", "Cli Test", "--assessment-date", "2026-10-18",
                         "--format", "JSON", "Markdown"], gcloud=FakeGcloud(healthy()))
            self.assertEqual(0, code)
            self.assertTrue((Path(d) / "Cli-Test-2026-10-18" / "Cli-Test-2026-10-18-Assessment.md").exists())

    def test_cli_rejects_bad_input(self):
        for argv in (["--project-id", "BAD ID"], ["--folder-id", "abc"], ["--impersonate-service-account", "not-an-email"]):
            with self.subTest(argv), self.assertRaises(SystemExit):
                main(argv + ["--no-prompt", "--no-export"], gcloud=FakeGcloud(healthy()))

    def test_cli_reports_a_clean_error_and_exit_code_when_not_signed_in(self):
        fx = healthy(); fx["auth list --filter=status:ACTIVE"] = []
        self.assertEqual(1, main(["--project-id", PROJECT, "--no-prompt", "--no-export"], gcloud=FakeGcloud(fx)))


if __name__ == "__main__":
    unittest.main()
