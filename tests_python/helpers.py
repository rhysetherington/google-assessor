"""Shared helpers for the per-domain check tests: build a fake project, break one setting, run one domain."""

import unittest
from datetime import datetime, timedelta, timezone

from google_gap_assessment.cloud.checks.common import Context
from google_gap_assessment.model import Options
from tests_python.fakes import (DEFAULT_COMPUTE_SA, DENIED, DISABLED, KEYS_KEY, PROJECT, SA, Err, FakeGcloud, add_binding, healthy)

RECENT = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
ANCIENT = (datetime.now(timezone.utc) - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
ORG = "org-policies describe {} --effective".format
ORG_V1 = "resource-manager org-policies describe {} --effective".format
INST = "compute instances list"
FW = "compute firewall-rules list"


def vm(fx):
    return fx[INST][0]


def key(fx, created):
    fx[KEYS_KEY] = [{"name": f"projects/p/serviceAccounts/{SA}/keys/abc123", "keyType": "USER_MANAGED", "validAfterTime": created}]


def fw(fx, **rule):
    base = {"network": ".../vpc-main", "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"]}
    fx[FW].append({**base, **rule})


def meta(fx, k, v):
    vm(fx)["metadata"]["items"].append({"key": k, "value": v})


def run(module, mutate=None, options=None, projects=(PROJECT,)):
    fx = healthy()
    if mutate:
        mutate(fx)
    gcloud = FakeGcloud(fx)
    return module.collect(Context(gcloud, options or Options()), list(projects)), gcloud




def run_cases(test: unittest.TestCase, module, cases) -> None:
    """Each case: (name, finding id, expected status, mutate, options, text that must appear in affected/detail)."""
    for name, finding_id, status, mutate, options, text in cases:
        with test.subTest(name):
            findings, _ = run(module, mutate, options)
            matching = [f for f in findings if f["FindingId"] == finding_id]
            test.assertEqual(1, len(matching), f"{finding_id} should be produced exactly once")
            f = matching[0]
            test.assertEqual(status, f["Status"], f"detail: {f['Detail']}; affected: {f['AffectedObjects']}")
            if text:
                test.assertIn(text, " | ".join(f["AffectedObjects"] + [f["Detail"]]))


def healthy_passes(test: unittest.TestCase, module) -> None:
    """A project that meets every check reports only passes, and the collector only makes read-only calls."""
    findings, gcloud = run(module)
    test.assertGreater(len(findings), 0)
    test.assertEqual([], [f"{f['FindingId']}={f['Status']}: {f['Detail']}" for f in findings if f["Status"] != "Pass"])
    test.assertGreater(len(gcloud.calls), 0)  # FakeGcloud raises AssertionError on a write verb, so reaching here proves read-only
