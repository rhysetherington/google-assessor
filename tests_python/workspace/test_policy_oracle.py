"""Our Policy API reducer against real API responses and their expected reduced results (CISA ScubaGoggles' test data, CC0).

This is an independent oracle: the fixtures were produced by a different implementation against Google's real API, so agreement here
means the reducer reads sort order, merge, max-map, group and nested-OU rules the way Google defines them.
"""

import json
import unittest
from pathlib import Path

from google_gap_assessment.workspace.policy import reduce_policies

DATA = Path(__file__).parent.parent / "data" / "policy_api"
# Sections whose expected value is post-processed by that implementation's own parsers (resolving list ids to addresses, deriving
# "enabled" from rule states, injecting defaults for service status), so only their raw shape differs.
PARSED_BY_THEIRS = {"gmail_blocked_sender_lists", "gmail_spam_override_lists", "gmail_comprehensive_mail_storage", "rule_system_defined_alerts", "dlp_pii"}


def their_label(path: str) -> str:
    """The reference implementation names scopes by OU name, with the parent path for nested OUs."""
    if path == "/":
        return "topOU"
    name = path.strip("/").split("/")[-1]
    return name if path.count("/") == 1 else f"{name} (in {path.strip('/').removesuffix('/' + name)})"


def reduced_by_us(fixture: dict) -> dict:
    pages = fixture.get("responses") or [fixture["response"]]
    raw = [p for page in pages for p in page.get("policies", [])]
    ou_paths = {k: v["path"] for k, v in fixture["orgunits"].items()}
    scopes = reduce_policies(raw, ou_paths, fixture.get("groups", {})).scopes
    labels = {path: their_label(path) for path in ou_paths.values()}
    out = {}
    for label, values in scopes.items():
        base, _, group = label.partition(" (group ")
        out[labels.get(base, base) + (f" (group {group}" if group else "")] = {k.replace(".", "_"): v for k, v in values.items()}
    return out


def canonical(value):
    return json.dumps(sorted(json.dumps(i, sort_keys=True) for i in value)) if isinstance(value, list) else json.dumps(value, sort_keys=True)


class AgainstRealResponses(unittest.TestCase):
    def test_reducer_reproduces_the_expected_result(self):
        compared = 0
        for path in sorted(DATA.glob("scuba_policy_response_*.json")):
            fixture = json.loads(path.read_text())
            ours = reduced_by_us(fixture)
            for scope, sections in fixture["results"].items():
                for section, expected in sections.items():
                    if section in PARSED_BY_THEIRS or section.endswith("_service_status"):
                        continue
                    with self.subTest(file=path.name, scope=scope, section=section):
                        got = ours.get(scope, {}).get(section)
                        self.assertIsNotNone(got, f"{section} missing for {scope}")
                        self.assertEqual(canonical(expected), canonical(got))
                        compared += 1
        self.assertGreater(compared, 30, "the oracle compared too little to mean anything")

    def test_max_map_combines_partial_rule_state_lists_from_several_policies(self):
        fixture = json.loads((DATA / "scuba_policy_response_4.json").read_text())
        states = reduced_by_us(fixture)["topOU"]["gmail_rule_states"]["ruleStates"]
        self.assertEqual(12, len(states))  # 5 from the highest-priority policy, 7 more from the lower one
        self.assertEqual(len(states), len({s["ruleId"] for s in states}))

    def test_nested_ous_and_groups_get_their_own_scopes(self):
        fixture = json.loads((DATA / "scuba_policy_response_2.json").read_text())
        ours = reduced_by_us(fixture)
        self.assertTrue(any("(group " in label for label in ours), "group-targeted policies should have their own scope")
        self.assertIn("1-1-1-1 (in 1/1-1/1-1-1)", ours)


if __name__ == "__main__":
    unittest.main()
