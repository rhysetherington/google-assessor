"""Networking (NET-001..NET-008) against the fake gcloud. Each case starts from a project that meets every check and breaks one setting, so a
failing case names the rule that regressed. An unreadable setting is NotAssessed, never a pass.

To redo or extend one check, find its id below. The check itself is the function registered for that id in
gcp_gap_assessment/checks/network.py."""

import unittest

from gcp_gap_assessment.checks import network as MODULE
from tests_python.helpers import healthy_passes, run_cases, DENIED, DISABLED, FW, fw

# (name, finding id, expected status, mutate(fixtures), options, text that must appear in affected/detail)
CASES = [
    ("NET-001 gap: default network", "NET-001", "Gap", lambda f: f["compute networks list"].append({"name": "default"}), None, None),
    ("NET-002 gap: legacy network", "NET-002", "Gap", lambda f: f["compute networks list"].append({"name": "old", "IPv4Range": "10.0.0.0/16"}), None, None),
    ("NET-003 gap: SSH open", "NET-003", "Gap", lambda f: fw(f, name="open-ssh", allowed=[{"IPProtocol": "tcp", "ports": ["22"]}]), None, "open-ssh"),
    ("NET-003 gap: SSH inside a port range", "NET-003", "Gap", lambda f: fw(f, name="r", allowed=[{"IPProtocol": "tcp", "ports": ["20-30"]}]), None, None),
    ("NET-003 pass: only HTTPS open", "NET-003", "Pass", lambda f: fw(f, name="web", allowed=[{"IPProtocol": "tcp", "ports": ["443"]}]), None, None),
    ("NET-003 pass: disabled rule", "NET-003", "Pass", lambda f: fw(f, name="off", disabled=True, allowed=[{"IPProtocol": "tcp", "ports": ["22"]}]), None, None),
    ("NET-003 pass: egress rule", "NET-003", "Pass",
     lambda f: fw(f, name="out", direction="EGRESS", sourceRanges=None, destinationRanges=["0.0.0.0/0"], allowed=[{"IPProtocol": "tcp", "ports": ["22"]}]), None, None),
    ("NET-004 gap: RDP open", "NET-004", "Gap", lambda f: fw(f, name="rdp", allowed=[{"IPProtocol": "tcp", "ports": ["3389"]}]), None, None),
    ("NET-005 gap: all protocols open", "NET-005", "Gap", lambda f: fw(f, name="any", allowed=[{"IPProtocol": "all"}]), None, None),
    ("NET-005 gap: tcp with no ports", "NET-005", "Gap", lambda f: fw(f, name="allports", allowed=[{"IPProtocol": "tcp"}]), None, None),
    ("NET-006 gap: flow logs off", "NET-006", "Gap", lambda f: f["compute networks subnets list"][0]["logConfig"].__setitem__("enable", False), None, None),
    ("NET-006 gap: no logConfig", "NET-006", "Gap", lambda f: f["compute networks subnets list"][0].pop("logConfig"), None, None),
    ("NET-006 pass: proxy-only subnet", "NET-006", "Pass",
     lambda f: f["compute networks subnets list"].append({"name": "proxy", "region": ".../europe-west2", "purpose": "REGIONAL_MANAGED_PROXY"}), None, None),
    ("NET-007 gap: DNSSEC off", "NET-007", "Gap", lambda f: f["dns managed-zones list"][0]["dnssecConfig"].__setitem__("state", "off"), None, None),
    ("NET-007 pass: private zone", "NET-007", "Pass", lambda f: f["dns managed-zones list"].append({"name": "internal", "visibility": "private"}), None, None),
    ("NET-008 gap: RSASHA1", "NET-008", "Gap", lambda f: f["dns managed-zones list"][0]["dnssecConfig"]["defaultKeySpecs"][0].__setitem__("algorithm", "rsasha1"), None, None),
    ("NET-001 pass (not applicable): Compute API disabled", "NET-001", "Pass", lambda f: f.__setitem__("compute networks list", DISABLED), None, "Not applicable"),
    ("NET-003 NotAssessed: firewall unreadable", "NET-003", "NotAssessed", lambda f: f.__setitem__(FW, DENIED), None, None),
]


class NetworkChecks(unittest.TestCase):
    def test_healthy_project_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
