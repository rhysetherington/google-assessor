"""The whole Workspace flow: a Workspace-only run, a combined run, choosing the scope, connecting (scopes and roles), and the reports."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from google_gap_assessment import report
from google_gap_assessment.__main__ import choose_scope, main
from google_gap_assessment.assess import CLOUD_DOMAINS, WORKSPACE_DOMAINS, export_assessment, run_assessment
from google_gap_assessment.errors import ApiError
from google_gap_assessment.model import CONTROL_MAPPING
from google_gap_assessment.workspace import auth
from google_gap_assessment.workspace.session import connect_workspace
from tests_python.fakes import PROJECT, FakeGcloud, healthy
from tests_python.workspace.ws_fakes import CI, DENIED, DISABLED, TENANT, Err, FakeResolver, FakeWorkspace, Tenant

WS_CHECKS = sum(1 for c in CONTROL_MAPPING.values() if c["source"] == "workspace")
ALL_SCOPES_INFO = {"scope": " ".join(auth.SCOPES), "email": "admin@contoso.com"}


def quiet(fn, *a, **k):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*a, **k)


class WorkspaceOnly(unittest.TestCase):
    def test_a_healthy_tenant_meets_every_workspace_check(self):
        a = run_assessment(workspace=Tenant().session(), no_prompt=True)
        self.assertEqual(WS_CHECKS, a["Summary"]["TotalChecks"])
        self.assertEqual([], [f"{f['FindingId']}={f['Status']}: {f['Detail']}" for f in a["Findings"] if f["Status"] != "Pass"])
        self.assertEqual(100, a["Score"])
        self.assertEqual(["workspace"], a["Scope"]["Targets"])
        self.assertEqual([], a["Scope"]["Projects"])
        self.assertEqual(TENANT, a["Scope"]["Workspace"]["PrimaryDomain"])

    def test_every_workspace_domain_ran(self):
        a = run_assessment(workspace=Tenant().session(), no_prompt=True)
        self.assertEqual(set(WORKSPACE_DOMAINS), set(a["Domains"]))
        self.assertTrue(all(f["Source"] == "workspace" for f in a["Findings"]))

    def test_the_client_name_defaults_to_the_primary_domain(self):
        self.assertEqual("contoso", run_assessment(workspace=Tenant().session(), no_prompt=True)["Metadata"]["ClientName"])

    def test_gaps_are_found_and_scored(self):
        t = Tenant(); t.settings["gmail.auto_forwarding"] = {"enableAutoForwarding": True}; t.user("alice@contoso.com")["isEnrolledIn2Sv"] = False
        a = run_assessment(workspace=t.session(), no_prompt=True)
        self.assertEqual({"GML-028", "GID-005"}, {f["FindingId"] for f in a["Findings"] if f["Status"] == "Gap"})
        self.assertLess(a["Score"], 100)

    def test_a_workspace_run_never_touches_gcloud(self):
        gcloud = FakeGcloud(healthy())
        run_assessment(gcloud=None, workspace=Tenant().session(), no_prompt=True)
        self.assertEqual([], gcloud.calls)

    def test_domains_needing_the_other_target_are_refused_clearly(self):
        with self.assertRaisesRegex(ValueError, "need Google Cloud access"):
            run_assessment(workspace=Tenant().session(), domains=["Iam"], no_prompt=True)
        with self.assertRaisesRegex(ValueError, "need a Google Workspace connection"):
            run_assessment(FakeGcloud(healthy()), [PROJECT], domains=["Identity"], no_prompt=True)

    def test_redoing_one_workspace_check_runs_only_that_check_and_is_labelled(self):
        t = Tenant(); t.settings["gmail.auto_forwarding"] = {"enableAutoForwarding": True}
        session = t.session()
        a = run_assessment(workspace=session, check_ids=["gml-028"], no_prompt=True)
        self.assertEqual(["GML-028"], [f["FindingId"] for f in a["Findings"]])
        self.assertEqual(["Gmail"], a["Domains"])
        self.assertIn("PARTIAL ASSESSMENT", report.to_markdown(a))
        self.assertNotIn("/admin/directory/v1/users", " ".join(session.ctx.client.requests))  # only what the check needs was read

    def test_a_session_whose_settings_cannot_be_read_gives_not_assessed_never_pass(self):
        t = Tenant(); t.fail(f"{CI}/policies", DENIED)
        a = run_assessment(workspace=t.session(), no_prompt=True)
        policy_checks = [f for f in a["Findings"] if f["FindingId"] == "GML-028"]
        self.assertEqual("NotAssessed", policy_checks[0]["Status"])
        # checks that do not need the settings still run
        self.assertEqual("Pass", next(f for f in a["Findings"] if f["FindingId"] == "GID-005")["Status"])


class WorkspaceAndCloud(unittest.TestCase):
    def test_both_targets_in_one_assessment(self):
        a = run_assessment(FakeGcloud(healthy()), [PROJECT], workspace=Tenant().session(), no_prompt=True)
        self.assertEqual(["workspace", "cloud"], a["Scope"]["Targets"])
        self.assertEqual(WS_CHECKS + 45, a["Summary"]["TotalChecks"])
        self.assertEqual(100, a["Score"])
        self.assertEqual({"workspace", "cloud"}, {f["Source"] for f in a["Findings"]})
        self.assertIn("admin@contoso.com", a["AssessedBy"])
        self.assertIn("assessor@contoso.com", a["AssessedBy"])

    def test_the_report_covers_both(self):
        a = run_assessment(FakeGcloud(healthy()), [PROJECT], workspace=Tenant().session(), no_prompt=True, client_name="Both")
        md = report.to_markdown(a)
        self.assertIn("Google Workspace tenant contoso.com", md)
        self.assertIn("1 Google Cloud project", md)
        self.assertIn("## Google Workspace Tenant", md)
        self.assertIn("## Projects Assessed", md)

    def test_a_workspace_only_report_has_no_projects_section(self):
        a = run_assessment(workspace=Tenant().session(), no_prompt=True)
        md, html = report.to_markdown(a), report.to_html(a)
        self.assertNotIn("Projects Assessed", md)
        self.assertNotIn("Projects assessed", html)
        self.assertIn("Google Workspace tenant", md)

    def test_files_are_written_for_a_workspace_run(self):
        t = Tenant(); t.settings["gmail.auto_forwarding"] = {"enableAutoForwarding": True}
        a = run_assessment(workspace=t.session(), no_prompt=True, client_name="Ws Only", assessment_date="2026-10-20")
        with tempfile.TemporaryDirectory() as d:
            files = export_assessment(a, Path(d), ["JSON", "Markdown", "HTML"], include_evidence=True)
            self.assertTrue((Path(d) / "Ws-Only-2026-10-20" / "evidence" / "GML-028.csv").exists())
            self.assertEqual(5, len(files))  # evidence file + index, json, md, html


class ChoosingTheScope(unittest.TestCase):
    def args(self, *argv):
        from google_gap_assessment.__main__ import build_parser
        return build_parser().parse_args(list(argv))

    def test_explicit_scope_wins(self):
        for s in ("workspace", "both", "cloud"):
            self.assertEqual(s, choose_scope(self.args("--scope", s), interactive=False))

    def test_it_is_inferred_from_the_checks_or_domains_asked_for(self):
        self.assertEqual("workspace", choose_scope(self.args("--check", "GML-028"), False))
        self.assertEqual("cloud", choose_scope(self.args("--check", "IAM-003"), False))
        self.assertEqual("both", choose_scope(self.args("--check", "GML-028", "IAM-003"), False))
        self.assertEqual("workspace", choose_scope(self.args("--domain", "Gmail", "Drive"), False))

    def test_it_is_inferred_from_which_options_were_given(self):
        self.assertEqual("cloud", choose_scope(self.args("--project-id", PROJECT), False))
        self.assertEqual("workspace", choose_scope(self.args("--quota-project", "my-quota-project"), False))
        self.assertEqual("both", choose_scope(self.args("--project-id", PROJECT, "--quota-project", "my-quota-project"), False))

    def test_it_asks_when_nothing_says_and_repeats_until_valid(self):
        answers = iter(["", "9", "2"])
        self.assertEqual("both", quiet(choose_scope, self.args(), True, lambda _p: next(answers)))
        for text, expected in (("1", "workspace"), ("2", "both"), ("3", "cloud")):
            self.assertEqual(expected, quiet(choose_scope, self.args(), True, lambda _p, t=text: t))

    def test_it_refuses_to_guess_when_it_cannot_ask(self):
        with self.assertRaisesRegex(RuntimeError, "--scope"):
            choose_scope(self.args(), interactive=False)


class CommandLine(unittest.TestCase):
    def run_main(self, *argv, **kw):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv), **kw)
        return code, out.getvalue(), err.getvalue()

    def test_workspace_only_run(self):
        with tempfile.TemporaryDirectory() as d:
            code, out, _ = self.run_main("--scope", "workspace", "--no-prompt", "--export-path", d, "--client-name", "Ws", "--assessment-date", "2026-10-20",
                                         workspace=Tenant().session())
            self.assertEqual(0, code)
            self.assertIn(f"{WS_CHECKS} checks", out)
            self.assertTrue((Path(d) / "Ws-2026-10-20" / "Ws-2026-10-20-Assessment.md").exists())

    def test_combined_run(self):
        code, out, _ = self.run_main("--scope", "both", "--project-id", PROJECT, "--no-prompt", "--no-export", workspace=Tenant().session(), gcloud=FakeGcloud(healthy()))
        self.assertEqual(0, code)
        self.assertIn(f"{WS_CHECKS + 45} checks", out)

    def test_cloud_only_run_does_not_connect_to_workspace(self):
        code, out, _ = self.run_main("--scope", "cloud", "--project-id", PROJECT, "--no-prompt", "--no-export", gcloud=FakeGcloud(healthy()))
        self.assertEqual(0, code)
        self.assertIn("45 checks", out)

    def test_a_scope_that_cannot_satisfy_the_requested_domains_is_an_error(self):
        code, _, err = self.run_main("--scope", "cloud", "--domain", "Gmail", "--no-prompt", "--no-export", gcloud=FakeGcloud(healthy()))
        self.assertEqual(1, code)
        self.assertIn("--scope both", err)

    def test_setup_help_and_list_checks_need_no_credentials(self):
        code, out, _ = self.run_main("--setup-help", "--quota-project", "my-quota-project")
        self.assertEqual(0, code)
        self.assertIn("my-quota-project", out)
        self.assertIn("cloud-identity.policies.readonly", out)
        code, out, _ = self.run_main("--list-checks")
        self.assertEqual(len(CONTROL_MAPPING), len(out.strip().splitlines()))
        self.assertIn("GML-028  Gmail", out)
        self.assertIn("IAM-003  Iam", out)


class Connecting(unittest.TestCase):
    def connect(self, tenant=None, info=None, **kw):
        tenant = tenant or Tenant()
        warnings = []
        client = FakeWorkspace(tenant.routes())
        kw.setdefault("resolver", FakeResolver({}))
        session = connect_workspace(client=client, token_provider=lambda: "tok", info_post=lambda url, data: info if info is not None else ALL_SCOPES_INFO,
                                    warn=warnings.append, **kw)
        return session, warnings

    def test_discovers_the_tenant(self):
        t = Tenant(); t.domains = [{"domainName": "contoso.com", "isPrimary": True, "verified": True, "domainAliases": [{"domainAliasName": "contoso.net"}]},
                                  {"domainName": "contoso.io", "isPrimary": False, "verified": True}, {"domainName": "pending.example", "verified": False}]
        s, w = self.connect(t)
        self.assertEqual(("C0123abcd", "contoso.com", "admin@contoso.com"), (s.customer_id, s.primary_domain, s.account))
        self.assertEqual(["contoso.com", "contoso.io", "contoso.net"], s.domains)  # unverified domains are not checked
        self.assertEqual([], w)

    def test_a_token_with_none_of_the_scopes_gets_the_setup_instructions(self):
        with self.assertRaisesRegex(RuntimeError, "(?s)none of the read-only Workspace scopes.*gcloud auth application-default login"):
            self.connect(info={"scope": "openid email"})

    def test_a_token_with_some_scopes_proceeds_with_a_warning_per_missing_scope(self):
        granted = list(auth.SCOPES)[:-2]
        s, warnings = self.connect(info={"scope": " ".join(granted), "email": "a@b.c"})
        self.assertEqual(2, len(warnings))
        self.assertIn(list(auth.SCOPES)[-1], warnings[1])
        self.assertEqual("contoso.com", s.primary_domain)

    def test_missing_sign_in_is_explained(self):
        def no_token():
            raise ApiError("No Application Default Credentials.", "Auth")
        with self.assertRaisesRegex(RuntimeError, "One-time setup"):
            connect_workspace(client=FakeWorkspace(Tenant().routes()), token_provider=no_token)

    def test_not_being_a_super_admin_is_explained(self):
        t = Tenant(); t.fail("https://admin.googleapis.com/admin/directory/v1/customers/my_customer", DENIED)
        with self.assertRaisesRegex(RuntimeError, "Super Admin"):
            self.connect(t)

    def test_a_disabled_api_is_explained(self):
        t = Tenant(); t.fail("https://admin.googleapis.com/admin/directory/v1/customers/my_customer", DISABLED)
        with self.assertRaisesRegex(RuntimeError, "gcloud services enable"):
            self.connect(t)

    def test_dns_can_be_switched_off(self):
        s, _ = self.connect(check_dns=False, resolver=None)
        self.assertFalse(s.ctx.options.check_dns)
        self.assertIsNone(s.ctx.resolver)


if __name__ == "__main__":
    unittest.main()
