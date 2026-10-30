"""Cloud KMS (KMS-001, KMS-002) against the fake gcloud. Each case starts from a project that meets every check and breaks one setting, so a
failing case names the rule that regressed. An unreadable setting is NotAssessed, never a pass.

To redo or extend one check, find its id below. The check itself is the function registered for that id in
google_gap_assessment/checks/kms.py."""

import unittest

from google_gap_assessment.cloud.checks import kms as MODULE
from tests_python.helpers import healthy_passes, run_cases, key

# (name, finding id, expected status, mutate(fixtures), options, text that must appear in affected/detail)
CASES = [
    ("KMS-001 gap: key usable by allUsers", "KMS-001", "Gap",
     lambda f: f["kms keys get-iam-policy key1 --keyring=ring1 --location=global"].__setitem__("bindings", [{"role": "roles/cloudkms.cryptoKeyDecrypter", "members": ["allUsers"]}]), None, None),
    ("KMS-002 gap: no rotation period", "KMS-002", "Gap", lambda f: f["kms keys list --keyring=ring1 --location=global"][0].pop("rotationPeriod"), None, None),
    ("KMS-002 gap: yearly rotation", "KMS-002", "Gap", lambda f: f["kms keys list --keyring=ring1 --location=global"][0].__setitem__("rotationPeriod", "31536000s"), None, None),
    ("KMS-002 pass: asymmetric keys do not auto-rotate", "KMS-002", "Pass",
     lambda f: (f["kms keys list --keyring=ring1 --location=global"][0].__setitem__("purpose", "ASYMMETRIC_SIGN"), f["kms keys list --keyring=ring1 --location=global"][0].pop("rotationPeriod")), None, None),
]


class KmsChecks(unittest.TestCase):
    def test_healthy_project_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
