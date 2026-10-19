"""Organization policy (ORG-001..ORG-009) against the fake gcloud. Each case starts from a project that meets every check and breaks one setting, so a
failing case names the rule that regressed. An unreadable setting is NotAssessed, never a pass.

To redo or extend one check, find its id below. The check itself is the function registered for that id in
gcp_gap_assessment/checks/orgpolicy.py."""

import unittest

from gcp_gap_assessment.checks import orgpolicy as MODULE
from tests_python.helpers import healthy_passes, run_cases, DENIED, DISABLED, Err, ORG, ORG_V1, key

# (name, finding id, expected status, mutate(fixtures), options, text that must appear in affected/detail)
CASES = [
    ("ORG-001 gap: key creation not blocked", "ORG-001", "Gap", lambda f: f[ORG("iam.disableServiceAccountKeyCreation")]["spec"]["rules"][0].__setitem__("enforce", False), None, None),
    ("ORG-002 gap: only under a condition", "ORG-002", "Gap",
     lambda f: f[ORG("storage.publicAccessPrevention")]["spec"]["rules"][0].__setitem__("condition", {"expression": "x"}), None, None),
    ("ORG-003 gap: no policy set (NOT_FOUND)", "ORG-003", "Gap", lambda f: f.__setitem__(ORG("compute.requireOsLogin"), Err("NotFound", "NOT_FOUND")), None, None),
    ("ORG-004 gap: external IPs not denied", "ORG-004", "Gap", lambda f: f.__setitem__(ORG("compute.vmExternalIpAccess"), {"spec": {"rules": [{"allowAll": True}]}}), None, None),
    ("ORG-005 gap: no allowed member domains", "ORG-005", "Gap", lambda f: f.__setitem__(ORG("iam.allowedPolicyMemberDomains"), {"spec": {"rules": [{"allowAll": True}]}}), None, None),
    ("ORG-006 gap: public SQL IPs not restricted", "ORG-006", "Gap", lambda f: f[ORG("sql.restrictPublicIp")]["spec"]["rules"][0].__setitem__("enforce", False), None, None),
    ("ORG-009 NotAssessed: policy unreadable", "ORG-009", "NotAssessed", lambda f: f.__setitem__(ORG("iam.automaticIamGrantsForDefaultServiceAccounts"), DENIED), None, None),
    ("ORG-001 NotAssessed: Org Policy API disabled and legacy command unreadable", "ORG-001", "NotAssessed",
     lambda f: (f.__setitem__(ORG("iam.disableServiceAccountKeyCreation"), DISABLED), f.__setitem__(ORG_V1("iam.disableServiceAccountKeyCreation"), DENIED)), None, None),
    # Fallback: a new project has no Organization Policy API, so the legacy command answers instead.
    ("ORG-001 pass via legacy command when the v2 API is disabled", "ORG-001", "Pass",
     lambda f: (f.__setitem__(ORG("iam.disableServiceAccountKeyCreation"), DISABLED),
                f.__setitem__(ORG_V1("iam.disableServiceAccountKeyCreation"), {"booleanPolicy": {"enforced": True}})), None, None),
    ("ORG-001 gap via legacy command when the v2 API is disabled", "ORG-001", "Gap",
     lambda f: (f.__setitem__(ORG("iam.disableServiceAccountKeyCreation"), DISABLED), f.__setitem__(ORG_V1("iam.disableServiceAccountKeyCreation"), {})), None, None),
    ("ORG-004 pass via legacy: deny all values", "ORG-004", "Pass",
     lambda f: (f.__setitem__(ORG("compute.vmExternalIpAccess"), DISABLED), f.__setitem__(ORG_V1("compute.vmExternalIpAccess"), {"listPolicy": {"allValues": "DENY"}})), None, None),
    ("ORG-004 gap via legacy: all values allowed", "ORG-004", "Gap",
     lambda f: (f.__setitem__(ORG("compute.vmExternalIpAccess"), DISABLED), f.__setitem__(ORG_V1("compute.vmExternalIpAccess"), {"listPolicy": {"allValues": "ALLOW"}})), None, None),
    ("ORG-005 pass via legacy: allowed domains listed", "ORG-005", "Pass",
     lambda f: (f.__setitem__(ORG("iam.allowedPolicyMemberDomains"), DISABLED), f.__setitem__(ORG_V1("iam.allowedPolicyMemberDomains"), {"listPolicy": {"allowedValues": ["C0123"]}})), None, None),
    ("ORG-005 gap via legacy: nothing restricted", "ORG-005", "Gap",
     lambda f: (f.__setitem__(ORG("iam.allowedPolicyMemberDomains"), DISABLED), f.__setitem__(ORG_V1("iam.allowedPolicyMemberDomains"), {"listPolicy": {"allValues": "ALLOW"}})), None, None),
    ("ORG-001 NotAssessed: permission denied is not retried on the legacy command", "ORG-001", "NotAssessed",
     lambda f: f.__setitem__(ORG("iam.disableServiceAccountKeyCreation"), DENIED), None, None),
]


class OrgPolicyChecks(unittest.TestCase):
    def test_healthy_project_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
