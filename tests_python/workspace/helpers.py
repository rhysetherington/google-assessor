"""Shared runner for the per-domain Workspace check tests: break one thing on a healthy tenant, run one domain, look at one finding."""

import unittest

from tests_python.workspace.ws_fakes import TENANT, Tenant


def run(module, mutate=None, options=None, only=None):
    tenant = Tenant()
    if mutate:
        mutate(tenant)
    ctx = tenant.context(options)
    return module.collect(ctx, [TENANT], only), ctx


def run_cases(test: unittest.TestCase, module, cases) -> None:
    """Each case: (name, finding id, expected status, mutate(tenant), options, text that must appear in affected/detail)."""
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
    """A tenant that meets every check reports only passes."""
    findings, ctx = run(module)
    test.assertGreater(len(findings), 0)
    test.assertEqual([], [f"{f['FindingId']}={f['Status']}: {f['Detail']}" for f in findings if f["Status"] != "Pass"])
    test.assertGreater(len(ctx.client.requests), 0)


# --- small mutations used by the per-domain tests ------------------------------------------------------------------------------

def setting(name, **fields):
    """Change fields of a top-level setting."""
    return lambda t: t.settings.__setitem__(name, {**t.settings.get(name, {}), **fields})


def drop(name):
    """Remove a setting entirely (so only Google's documented default, if any, remains)."""
    return lambda t: t.settings.pop(name)


def replace(name, value):
    return lambda t: t.settings.__setitem__(name, value)


def both(*fns):
    def mutate(t):
        for f in fns:
            f(t)
    return mutate


def off(service):
    """Switch a product off for the whole tenant."""
    return replace(service, {"serviceState": "DISABLED"})


def override(ou, name, value, group=None):
    return lambda t: t.override(ou, name, value, group=group)


def coverage_test(test, module, cases):
    """Every check of the module has at least one case that makes it report a gap."""
    test.assertEqual({chk.id for chk in module.CHECKS}, {c[1] for c in cases if c[2] == "Gap"})
