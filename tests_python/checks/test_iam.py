"""Identity and IAM (IAM-001..IAM-011) against the fake gcloud. Each case starts from a project that meets every check and breaks one setting, so a
failing case names the rule that regressed. An unreadable setting is NotAssessed, never a pass.

To redo or extend one check, find its id below. The check itself is the function registered for that id in
google_gap_assessment/checks/iam.py."""

import unittest

from google_gap_assessment.cloud.checks import iam as MODULE
from tests_python.helpers import healthy_passes, run_cases, ANCIENT, DEFAULT_COMPUTE_SA, DENIED, DISABLED, KEYS_KEY, Options, RECENT, SA, add_binding, key

# (name, finding id, expected status, mutate(fixtures), options, text that must appear in affected/detail)
CASES = [
    ("IAM-001 gap: Owner to a user", "IAM-001", "Gap", lambda f: add_binding(f, "roles/owner", "user:bob@contoso.com"), None, "bob@contoso.com"),
    ("IAM-001 gap: Editor to a group", "IAM-001", "Gap", lambda f: add_binding(f, "roles/editor", "group:devs@contoso.com"), None, None),
    ("IAM-001 pass: cloudservices account is Google-managed", "IAM-001", "Pass",
     lambda f: add_binding(f, "roles/editor", "serviceAccount:123456789012@cloudservices.gserviceaccount.com"), None, None),
    ("IAM-002 gap: user-managed SA with an admin role", "IAM-002", "Gap", lambda f: add_binding(f, "roles/compute.admin", f"serviceAccount:{SA}"), None, None),
    ("IAM-002 pass: default compute SA is IAM-008", "IAM-002", "Pass",
     lambda f: add_binding(f, "roles/editor", f"serviceAccount:{DEFAULT_COMPUTE_SA}"), None, None),
    ("IAM-008 gap: default compute SA has Editor", "IAM-008", "Gap", lambda f: add_binding(f, "roles/editor", f"serviceAccount:{DEFAULT_COMPUTE_SA}"), None, None),
    ("IAM-003 gap: allUsers", "IAM-003", "Gap", lambda f: add_binding(f, "roles/viewer", "allUsers"), None, "allUsers"),
    ("IAM-003 gap: allAuthenticatedUsers", "IAM-003", "Gap", lambda f: add_binding(f, "roles/viewer", "allAuthenticatedUsers"), None, None),
    ("IAM-006 gap: user has Service Account User", "IAM-006", "Gap", lambda f: add_binding(f, "roles/iam.serviceAccountUser", "user:alice@contoso.com"), None, None),
    ("IAM-006 gap: group has Token Creator", "IAM-006", "Gap", lambda f: add_binding(f, "roles/iam.serviceAccountTokenCreator", "group:ops@contoso.com"), None, None),
    ("IAM-007 gap: gmail.com with no corporate domain", "IAM-007", "Gap", lambda f: add_binding(f, "roles/viewer", "user:someone@gmail.com"), None, "gmail.com"),
    ("IAM-007 pass: corporate domains not given", "IAM-007", "Pass", None, None, None),
    ("IAM-007 gap: outside supplied corporate domains", "IAM-007", "Gap", None, Options(corporate_domains=["example.org"]), None),
    ("IAM-009 gap: same principal admin and user", "IAM-009", "Gap",
     lambda f: (add_binding(f, "roles/iam.serviceAccountAdmin", "user:carol@contoso.com"), add_binding(f, "roles/iam.serviceAccountUser", "user:carol@contoso.com")), None, None),
    ("IAM-009 pass: roles split between principals", "IAM-009", "Pass",
     lambda f: (add_binding(f, "roles/iam.serviceAccountAdmin", "user:carol@contoso.com"), add_binding(f, "roles/iam.serviceAccountUser", "user:dave@contoso.com")), None, None),
    ("IAM-004 gap: a user-managed key exists", "IAM-004", "Gap", lambda f: key(f, RECENT), None, None),
    ("IAM-005 pass: key is recent", "IAM-005", "Pass", lambda f: key(f, RECENT), None, None),
    ("IAM-005 gap: key older than 90 days", "IAM-005", "Gap", lambda f: key(f, ANCIENT), None, "abc123"),
    ("IAM-005 pass: limit raised to 500 days", "IAM-005", "Pass", lambda f: key(f, ANCIENT), Options(key_max_age_days=500), None),
    ("IAM-004 NotAssessed: keys cannot be listed", "IAM-004", "NotAssessed", lambda f: f.__setitem__(KEYS_KEY, DENIED), None, None),
    ("IAM-010 gap: unrestricted API key", "IAM-010", "Gap",
     lambda f: f.__setitem__("services api-keys list", [{"name": "projects/1/locations/global/keys/k1", "displayName": "Browser key", "createTime": RECENT}]), None, None),
    ("IAM-010 pass: key restricted to one API", "IAM-010", "Pass",
     lambda f: f.__setitem__("services api-keys list", [{"name": "k1", "createTime": RECENT, "restrictions": {"apiTargets": [{"service": "maps.googleapis.com"}]}}]), None, None),
    ("IAM-011 gap: API key older than 90 days", "IAM-011", "Gap",
     lambda f: f.__setitem__("services api-keys list", [{"name": "k1", "createTime": ANCIENT}]), None, None),
    ("IAM-010 pass (not applicable): API Keys API disabled", "IAM-010", "Pass", lambda f: f.__setitem__("services api-keys list", DISABLED), None, "Not applicable"),
    ("IAM-001 NotAssessed: IAM policy unreadable", "IAM-001", "NotAssessed", lambda f: f.__setitem__("projects get-iam-policy", DENIED), None, None),
]


class IamChecks(unittest.TestCase):
    def test_healthy_project_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
