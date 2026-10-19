"""The tool's central promise: it only reads. Plus the gateway's argument handling, error classification and retry,
and a scan of the source so a write command cannot be added without a test failing."""

import re
import unittest
from pathlib import Path

from gcp_gap_assessment.gcloud import Gcloud, GcloudError, classify_error, is_read_only

PACKAGE = Path(__file__).parent.parent / "gcp_gap_assessment"


class ReadOnlyGate(unittest.TestCase):
    def test_allowed(self):
        for c in ("compute instances list", "storage buckets get-iam-policy", "projects describe", "org-policies describe",
                  "iam service-accounts keys list", "auth list"):
            with self.subTest(c):
                self.assertTrue(is_read_only(c))

    def test_refused(self):
        for c in ("compute instances delete", "compute instances stop", "projects add-iam-policy-binding", "projects set-iam-policy",
                  "iam service-accounts keys create", "iam service-accounts create", "storage buckets update", "storage rm",
                  "secrets versions access", "kms decrypt", "auth print-access-token", "auth login", "config set", "services enable",
                  "compute ssh", "compute instances get-serial-port-output", "logging sinks create", "", "compute instances --foo list"):
            with self.subTest(c):
                self.assertFalse(is_read_only(c))

    def test_run_refuses_before_starting_any_process(self):
        def runner(_args):
            raise AssertionError("runner must not be reached")
        with self.assertRaisesRegex(ValueError, "read-only"):
            Gcloud(path="/fake/gcloud", runner=runner).run("compute instances delete", ["vm1"])


class Arguments(unittest.TestCase):
    def test_arguments_stay_separate_and_standard_flags_are_added(self):
        seen = []
        g = Gcloud(path="/fake/gcloud", runner=lambda a: (seen.append(list(a)) or (0, '[{"name": "vm1"}]', "")))
        out = g.run("compute instances list", ["--filter=name:vm; rm -rf /"], "test-project-one")
        self.assertEqual([{"name": "vm1"}], out)
        args = seen[0]
        self.assertEqual(["/fake/gcloud", "compute", "instances", "list"], args[:4])
        self.assertIn("--filter=name:vm; rm -rf /", args)  # one argument, never interpreted by a shell
        for expected in ("--project=test-project-one", "--format=json", "--quiet"):
            self.assertIn(expected, args)

    def test_impersonation_only_when_set(self):
        seen = []
        runner = lambda a: (seen.append(list(a)) or (0, "[]", ""))  # noqa: E731
        Gcloud(path="/g", runner=runner).run("projects list")
        Gcloud(path="/g", impersonate="ro@test-project-one.iam.gserviceaccount.com", runner=runner).run("projects list")
        self.assertFalse(any(a.startswith("--impersonate") for a in seen[0]))
        self.assertIn("--impersonate-service-account=ro@test-project-one.iam.gserviceaccount.com", seen[1])

    def test_empty_output_is_none_and_helpers_normalise(self):
        g = Gcloud(path="/g", runner=lambda a: (0, "", ""))
        self.assertIsNone(g.run("projects list"))
        self.assertEqual([], g.get_list("projects list"))
        self.assertEqual({}, g.get_one("projects describe", ["x"]))

    def test_results_and_failures_are_cached(self):
        calls = []
        g = Gcloud(path="/g", runner=lambda a: (calls.append(1) or (0, "[1]", "")))
        g.get("projects list"); g.get("projects list")
        self.assertEqual(1, len(calls))
        bad = []
        g2 = Gcloud(path="/g", runner=lambda a: (bad.append(1) or (1, "", "PERMISSION_DENIED")))
        for _ in range(2):
            with self.assertRaises(GcloudError):
                g2.get("projects list")
        self.assertEqual(1, len(bad))


class Errors(unittest.TestCase):
    def test_categories(self):
        cases = {
            "ApiDisabled": "ERROR: (gcloud.compute.instances.list) HttpError 403: Compute Engine API has not been used in project 1 before or it is disabled. SERVICE_DISABLED",
            "PermissionDenied": "ERROR: (gcloud.projects.get-iam-policy) PERMISSION_DENIED: The caller does not have permission",
            "NotFound": "ERROR: (gcloud.org-policies.describe) NOT_FOUND: Requested entity was not found.",
            "Auth": "ERROR: There was a problem refreshing your current auth tokens: Reauthentication required. Please run: gcloud auth login",
            "Other": "ERROR: something unexpected",
        }
        for category, text in cases.items():
            with self.subTest(category):
                self.assertEqual(category, classify_error(text).category)

    def test_throttling_is_retried_with_backoff_then_succeeds(self):
        outcomes = [(1, "", "RESOURCE_EXHAUSTED: Quota exceeded"), (1, "", "RESOURCE_EXHAUSTED: Quota exceeded"), (0, '[{"a": 1}]', "")]
        sleeps = []
        g = Gcloud(path="/g", runner=lambda a: outcomes.pop(0), sleep=sleeps.append)
        self.assertEqual([{"a": 1}], g.run("projects list"))
        self.assertEqual([2, 4], sleeps)

    def test_gives_up_after_the_retry_limit(self):
        g = Gcloud(path="/g", runner=lambda a: (1, "", "RESOURCE_EXHAUSTED"), sleep=lambda s: None)
        with self.assertRaises(GcloudError) as cm:
            g.run("projects list", max_retries=2)
        self.assertEqual("Transient", cm.exception.category)


class SourceScan(unittest.TestCase):
    def test_every_literal_command_in_the_source_is_read_only(self):
        found = 0
        for path in PACKAGE.rglob("*.py"):
            for command in re.findall(r"""gcloud\.(?:get|get_list|get_one|run)\(\s*["']([^"']+)["']""", path.read_text()):
                found += 1
                with self.subTest(file=path.name, command=command):
                    self.assertTrue(is_read_only(command))
        self.assertGreater(found, 25, "the scan found too few commands to be meaningful")

    def test_no_shell_or_dynamic_execution(self):
        for path in PACKAGE.rglob("*.py"):
            text = path.read_text()
            with self.subTest(file=path.name):
                self.assertNotRegex(text, r"shell\s*=\s*True|os\.system|os\.popen|\beval\(|\bexec\(")

    def test_only_the_gateway_and_connect_start_processes(self):
        users = sorted(p.name for p in PACKAGE.rglob("*.py") if "subprocess" in p.read_text() and p.name != "__init__.py")
        self.assertEqual(["gcloud.py"], users)


if __name__ == "__main__":
    unittest.main()
