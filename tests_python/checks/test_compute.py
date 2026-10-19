"""Compute Engine (CMP-001..CMP-008) against the fake gcloud. Each case starts from a project that meets every check and breaks one setting, so a
failing case names the rule that regressed. An unreadable setting is NotAssessed, never a pass.

To redo or extend one check, find its id below. The check itself is the function registered for that id in
gcp_gap_assessment/checks/compute.py."""

import unittest

from gcp_gap_assessment.checks import compute as MODULE
from tests_python.helpers import healthy_passes, run_cases, DEFAULT_COMPUTE_SA, DENIED, DISABLED, INST, SA, key, meta, vm

# (name, finding id, expected status, mutate(fixtures), options, text that must appear in affected/detail)
CASES = [
    ("CMP-001 gap: default compute SA", "CMP-001", "Gap", lambda f: vm(f)["serviceAccounts"][0].__setitem__("email", DEFAULT_COMPUTE_SA), None, None),
    ("CMP-002 gap: default SA with cloud-platform scope", "CMP-002", "Gap",
     lambda f: vm(f)["serviceAccounts"][0].update(email=DEFAULT_COMPUTE_SA, scopes=["https://www.googleapis.com/auth/cloud-platform"]), None, None),
    ("CMP-002 pass: dedicated SA with cloud-platform scope", "CMP-002", "Pass",
     lambda f: vm(f)["serviceAccounts"][0].__setitem__("scopes", ["https://www.googleapis.com/auth/cloud-platform"]), None, None),
    ("CMP-003 gap: project SSH keys not blocked, OS Login off", "CMP-003", "Gap",
     lambda f: (vm(f)["metadata"].__setitem__("items", []), f["compute project-info describe"]["commonInstanceMetadata"].__setitem__("items", [])), None, None),
    ("CMP-003 pass: OS Login on makes SSH keys irrelevant", "CMP-003", "Pass", lambda f: vm(f)["metadata"].__setitem__("items", []), None, None),
    ("CMP-004 gap: OS Login off at project", "CMP-004", "Gap", lambda f: f["compute project-info describe"]["commonInstanceMetadata"].__setitem__("items", []), None, None),
    ("CMP-004 gap: instance switches OS Login off", "CMP-004", "Gap", lambda f: meta(f, "enable-oslogin", "FALSE"), None, "FALSE"),
    ("CMP-005 gap: serial port on an instance", "CMP-005", "Gap", lambda f: meta(f, "serial-port-enable", "TRUE"), None, None),
    ("CMP-005 gap: serial port in project metadata", "CMP-005", "Gap",
     lambda f: f["compute project-info describe"]["commonInstanceMetadata"]["items"].append({"key": "serial-port-enable", "value": "true"}), None, None),
    ("CMP-006 gap: IP forwarding", "CMP-006", "Gap", lambda f: vm(f).__setitem__("canIpForward", True), None, None),
    ("CMP-007 gap: vTPM off", "CMP-007", "Gap", lambda f: vm(f)["shieldedInstanceConfig"].__setitem__("enableVtpm", False), None, None),
    ("CMP-007 gap: no Shielded VM config", "CMP-007", "Gap", lambda f: vm(f).pop("shieldedInstanceConfig"), None, None),
    ("CMP-008 gap: external IP", "CMP-008", "Gap",
     lambda f: vm(f)["networkInterfaces"][0].__setitem__("accessConfigs", [{"type": "ONE_TO_ONE_NAT", "natIP": "203.0.113.9"}]), None, None),
    ("CMP-008 pass: GKE nodes excluded", "CMP-008", "Pass",
     lambda f: f[INST].append({"name": "gke-node", "zone": ".../z", "labels": {"goog-gke-node": ""}, "canIpForward": True,
                               "networkInterfaces": [{"accessConfigs": [{"natIP": "203.0.113.10"}]}]}), None, None),
    ("CMP-001 pass (not applicable): Compute API disabled", "CMP-001", "Pass", lambda f: f.__setitem__(INST, DISABLED), None, "Not applicable"),
    ("CMP-006 NotAssessed: instances unreadable", "CMP-006", "NotAssessed", lambda f: f.__setitem__(INST, DENIED), None, None),
]


class ComputeChecks(unittest.TestCase):
    def test_healthy_project_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
