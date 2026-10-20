"""The Workspace plumbing: a GET-only client that refuses unknown hosts, error classification, retries, pagination, token handling,
the Policy API reducer and DNS parsing. No network, no Google account."""

import io
import json
import unittest
import urllib.error

from google_gap_assessment.errors import ApiError
from google_gap_assessment.workspace import auth, mail_dns, policy
from google_gap_assessment.workspace.client import ALLOWED_HOSTS, WorkspaceClient, classify_http_error
from google_gap_assessment.workspace.directory import Directory


class FakeResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode()
    def read(self): return self._body
    def __enter__(self): return self
    def __exit__(self, *a): return False


def http_error(status, payload, headers=None):
    return urllib.error.HTTPError("https://x", status, "err", headers or {}, io.BytesIO(json.dumps(payload).encode()))


class Opener:
    """Serves queued outcomes (a payload dict, or an exception to raise) and records every request."""
    def __init__(self, *outcomes): self.outcomes, self.requests = list(outcomes), []
    def __call__(self, request, timeout=None):
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception): raise outcome
        return FakeResponse(outcome)


def client(*outcomes, **kw):
    opener = Opener(*outcomes)
    sleeps = []
    return WorkspaceClient(lambda: "tok", opener=opener, sleep=sleeps.append, **kw), opener, sleeps


class ClientIsReadOnly(unittest.TestCase):
    def test_only_get_requests_are_ever_made_with_the_token_and_quota_project(self):
        c, opener, _ = client({"ok": 1}, quota_project="my-quota-proj")
        self.assertEqual({"ok": 1}, c.get("https://admin.googleapis.com/admin/directory/v1/users", {"customer": "my_customer"}))
        req = opener.requests[0]
        self.assertEqual("GET", req.get_method())
        self.assertIsNone(req.data)
        self.assertEqual("Bearer tok", req.get_header("Authorization"))
        self.assertEqual("my-quota-proj", req.get_header("X-goog-user-project"))
        self.assertIn("customer=my_customer", req.full_url)

    def test_hosts_outside_the_allowlist_and_plain_http_are_refused_before_any_request(self):
        c, opener, _ = client()
        for url in ("https://evil.example.com/x", "http://admin.googleapis.com/x", "https://admin.googleapis.com.evil.com/x", "ftp://admin.googleapis.com/x"):
            with self.subTest(url), self.assertRaises(ValueError):
                c.get(url)
        self.assertEqual([], opener.requests)

    def test_the_client_offers_no_way_to_use_another_method(self):
        import inspect
        self.assertEqual(["self", "url", "params"], list(inspect.signature(WorkspaceClient.get).parameters))
        self.assertEqual({"admin.googleapis.com", "cloudidentity.googleapis.com", "www.googleapis.com"}, set(ALLOWED_HOSTS))


class Errors(unittest.TestCase):
    def test_classification(self):
        cases = [
            (403, {"error": {"message": "Admin SDK API has not been used in project 1 before or it is disabled.", "errors": [{"reason": "accessNotConfigured"}]}}, "ApiDisabled"),
            (403, {"error": {"message": "Not Authorized to access this resource/api", "errors": [{"reason": "forbidden"}]}}, "PermissionDenied"),
            (403, {"error": {"message": "Request had insufficient authentication scopes.", "status": "PERMISSION_DENIED"}}, "PermissionDenied"),
            (401, {"error": {"message": "Invalid Credentials"}}, "Auth"),
            (404, {"error": {"message": "Resource Not Found: userKey"}}, "NotFound"),
            (429, {"error": {"message": "Rate Limit Exceeded", "errors": [{"reason": "rateLimitExceeded"}]}}, "Transient"),
            (503, {"error": {"message": "backend"}}, "Transient"),
            (400, {"error": {"message": "weird"}}, "Other"),
        ]
        for status, payload, category in cases:
            with self.subTest(status=status, category=category):
                self.assertEqual(category, classify_http_error(status, json.dumps(payload)).category)

    def test_non_json_error_body_is_survivable(self):
        self.assertEqual("Other", classify_http_error(400, "<html>nope</html>").category)

    def test_throttling_is_retried_with_backoff_then_succeeds(self):
        c, opener, sleeps = client(http_error(429, {"error": {"errors": [{"reason": "rateLimitExceeded"}]}}),
                                   http_error(503, {"error": {}}, {"Retry-After": "7"}), {"ok": True})
        self.assertEqual({"ok": True}, c.get("https://admin.googleapis.com/x"))
        self.assertEqual([2, 7.0], sleeps)

    def test_gives_up_after_the_retry_limit_and_permission_errors_are_not_retried(self):
        c, _, sleeps = client(*[http_error(429, {"error": {}})] * 3, max_retries=2)
        with self.assertRaises(ApiError) as cm:
            c.get("https://admin.googleapis.com/x")
        self.assertEqual("Transient", cm.exception.category)
        self.assertEqual(2, len(sleeps))
        c2, opener2, sleeps2 = client(http_error(403, {"error": {"errors": [{"reason": "forbidden"}]}}))
        with self.assertRaises(ApiError) as cm2:
            c2.get("https://admin.googleapis.com/x")
        self.assertEqual("PermissionDenied", cm2.exception.category)
        self.assertEqual([], sleeps2)

    def test_pagination_follows_next_page_token_and_pauses_when_asked(self):
        c, opener, sleeps = client({"items": [1], "nextPageToken": "t2"}, {"items": [2], "nextPageToken": "t3"}, {"items": [3]})
        self.assertEqual([1, 2, 3], c.items("https://admin.googleapis.com/x", page_delay=1.0))
        self.assertIn("pageToken=t3", opener.requests[2].full_url)
        self.assertEqual([1.0, 1.0], sleeps)

    def test_results_and_failures_are_cached(self):
        c, opener, _ = client({"a": 1})
        c.cached("https://admin.googleapis.com/x"); c.cached("https://admin.googleapis.com/x")
        self.assertEqual(1, len(opener.requests))
        c2, opener2, _ = client(http_error(403, {"error": {"errors": [{"reason": "forbidden"}]}}))
        for _ in range(2):
            with self.assertRaises(ApiError):
                c2.cached("https://admin.googleapis.com/y")
        self.assertEqual(1, len(opener2.requests))


class DirectoryRequestsOnlyWhatItNeeds(unittest.TestCase):
    def test_user_listing_asks_for_a_short_field_list(self):
        c, opener, _ = client({"users": [{"primaryEmail": "a@b.c"}]})
        Directory(c).users()
        url = opener.requests[0].full_url
        self.assertIn("fields=", url)
        for private in ("phones", "addresses", "name", "recoveryPhone", "emails"):
            self.assertNotIn(private, url.replace("primaryEmail", ""))


class Auth(unittest.TestCase):
    def test_token_is_cached_until_it_expires(self):
        calls, now = [], [0.0]
        provider = auth.AdcTokenProvider("/g", runner=lambda a: (calls.append(a) or (0, f"token{len(calls)}\n", "")), clock=lambda: now[0], ttl=100)
        self.assertEqual("token1", provider()); self.assertEqual("token1", provider())
        now[0] = 101
        self.assertEqual("token2", provider())
        self.assertEqual(["/g", "auth", "application-default", "print-access-token"], calls[0])

    def test_missing_credentials_are_explained(self):
        provider = auth.AdcTokenProvider("/g", runner=lambda a: (1, "", "Your default credentials were not found"))
        with self.assertRaises(ApiError) as cm:
            provider()
        self.assertEqual("Auth", cm.exception.category)

    def test_missing_scopes_are_listed(self):
        granted = set(list(auth.SCOPES)[:-2])
        self.assertEqual(list(auth.SCOPES)[-2:], auth.missing_scopes(granted))
        self.assertEqual(granted, auth.token_scopes("tok", post=lambda url, data: {"scope": " ".join(granted)}))

    def test_only_read_only_scopes_are_ever_requested(self):
        for scope in auth.SCOPES:
            self.assertTrue(scope.endswith(".readonly") or scope.endswith("/cloud-identity.policies.readonly") or ".readonly" in scope, scope)

    def test_setup_instructions_name_the_scopes_and_never_embed_a_secret(self):
        text = auth.setup_instructions("client_secret.json", "my-proj")
        for scope in auth.SCOPES:
            self.assertIn(scope, text)
        self.assertIn("--quota-project my-proj", text)
        self.assertIn("revoke", text)


class PolicyReducer(unittest.TestCase):
    def raw(self, ou, name, value, order=1, group=None):
        q = {"orgUnit": f"orgUnits/{ou}", "sortOrder": order}
        if group: q["group"] = f"groups/{group}"
        return {"policyQuery": q, "setting": {"type": f"settings/{name}", "value": value}}

    def reduce(self, raw):
        return policy.reduce_policies(raw, {"root": "/", "sales": "/Sales", "gone": "/Gone"}, {"g1": "team@example.com"})

    def test_highest_sort_order_wins_per_scope(self):
        ps = self.reduce([self.raw("root", "gmail.pop_access", {"enablePopAccess": True}, 1), self.raw("root", "gmail.pop_access", {"enablePopAccess": False}, 7)])
        self.assertFalse(ps.top("gmail.pop_access")["enablePopAccess"])

    def test_child_ou_and_group_overrides_are_labelled(self):
        ps = self.reduce([self.raw("root", "gmail.pop_access", {"enablePopAccess": False}),
                          self.raw("sales", "gmail.pop_access", {"enablePopAccess": True}, 2),
                          self.raw("root", "gmail.pop_access", {"enablePopAccess": True}, 3, group="g1")])
        self.assertEqual({"/Sales", "/ (group team@example.com)"}, {label for label, _ in ps.overrides("gmail.pop_access")})

    def test_merge_settings_fill_missing_fields_from_lower_priority_policies(self):
        ps = self.reduce([self.raw("root", "chat.chat_history", {"historyOnByDefault": True}, 1), self.raw("root", "chat.chat_history", {"allowUserModification": False}, 5)])
        self.assertEqual({"allowUserModification": False, "historyOnByDefault": True}, ps.top("chat.chat_history"))

    def test_non_merge_settings_do_not_borrow_from_lower_priority_policies(self):
        ps = self.reduce([self.raw("root", "gmail.pop_access", {"enablePopAccess": True, "extra": 1}, 1), self.raw("root", "gmail.pop_access", {"enablePopAccess": False}, 5)])
        self.assertEqual({"enablePopAccess": False}, ps.top("gmail.pop_access"))

    def test_rule_lists_keep_every_rule(self):
        ps = self.reduce([self.raw("root", "rule.dlp", {"displayName": "a"}), self.raw("root", "rule.dlp", {"displayName": "b"})])
        self.assertEqual(2, len(ps.top("rule.dlp")))

    def test_documented_defaults_fill_the_top_level_only(self):
        ps = self.reduce([self.raw("sales", "gmail.mail_delegation", {"enableMailDelegation": True})])
        self.assertFalse(ps.top("gmail.mail_delegation")["enableMailDelegation"])  # default
        self.assertEqual([("/Sales", {"enableMailDelegation": True})], ps.overrides("gmail.mail_delegation"))

    def test_policies_for_deleted_ous_are_ignored_and_policies_without_an_ou_are_top_level(self):
        ps = self.reduce([self.raw("nope", "gmail.pop_access", {"enablePopAccess": True}),
                          {"policyQuery": {"sortOrder": 1}, "setting": {"type": "settings/gmail.imap_access", "value": {"enableImapAccess": False}}}])
        self.assertIsNone(ps.top("gmail.pop_access"))
        self.assertFalse(ps.top("gmail.imap_access")["enableImapAccess"])

    def test_an_unknown_setting_with_no_default_is_none_not_a_guess(self):
        self.assertIsNone(self.reduce([]).top("gmail.pop_access"))


class Judge(unittest.TestCase):
    def ps(self, top, overrides=()):
        p = policy.PolicySet(); p.scopes["/"] = {"s": top}
        for label, value in overrides: p.scopes.setdefault(label, {})["s"] = value
        return p

    def test_compliant_everywhere(self):
        v = policy.judge(self.ps({"on": False}, [("/A", {"on": False})]), "s", lambda s: not s["on"])
        self.assertEqual((False, False, []), (v.unknown, v.unreadable_field, v.bad))

    def test_top_level_gap_and_override_gap_are_both_reported(self):
        v = policy.judge(self.ps({"on": True}, [("/A", {"on": True}), ("/B", {"on": False})]), "s", lambda s: not s["on"])
        self.assertEqual(["/", "/A"], [label for label, _ in v.bad])

    def test_an_override_is_judged_on_top_level_values_with_its_own_fields_on_top(self):
        v = policy.judge(self.ps({"a": False, "b": True}, [("/A", {"a": True})]), "s", lambda s: not s["a"] and s["b"])
        self.assertEqual(["/A"], [label for label, _ in v.bad])

    def test_missing_setting_and_missing_field_are_unknown_not_pass(self):
        self.assertTrue(policy.judge(policy.PolicySet(), "s", lambda s: True).unknown)
        self.assertTrue(policy.judge(self.ps({}), "s", lambda s: None).unreadable_field)


class Dns(unittest.TestCase):
    def resolver(self, answers_by_name):
        def opener(request, timeout=None):
            name = [p.split("=")[1] for p in request.full_url.split("?")[1].split("&") if p.startswith("name=")][0].replace("%2E", ".").replace("%5F", "_")
            data = answers_by_name.get(name)
            if data is None: return FakeResponse({"Status": 3})
            return FakeResponse({"Status": 0, "Answer": [{"type": 16, "data": d} for d in data]})
        return mail_dns.DohResolver(opener=opener, sleep=lambda s: None)

    def test_txt_strings_are_joined_and_nxdomain_is_empty(self):
        r = self.resolver({"example.com": ['"v=spf1 include:_spf.google.com " "~all"']})
        self.assertEqual(["v=spf1 include:_spf.google.com ~all"], r.txt("example.com"))
        self.assertEqual([], r.txt("missing.example.com"))

    def test_endpoint_must_be_https_and_names_are_validated(self):
        with self.assertRaises(ValueError): mail_dns.DohResolver("http://dns.example/q")
        with self.assertRaises(ValueError): self.resolver({}).txt("bad name; drop")

    def test_spf_dmarc_dkim_interpretation(self):
        self.assertEqual("~", mail_dns.spf_all_qualifier("v=spf1 include:_spf.google.com ~all"))
        self.assertEqual("-", mail_dns.spf_all_qualifier("v=spf1 -all"))
        self.assertEqual("+", mail_dns.spf_all_qualifier("v=spf1 +all"))
        self.assertIsNone(mail_dns.spf_all_qualifier("v=spf1 redirect=_spf.example.com"))
        self.assertEqual(1, len(mail_dns.spf_records(["google-site-verification=abc", "v=spf1 -all"])))
        self.assertEqual("reject", mail_dns.dmarc_record(["v=DMARC1; p=reject; rua=mailto:a@b.c"])["p"])
        self.assertIsNone(mail_dns.dmarc_record(["v=DMARC1; p=none", "v=DMARC1; p=reject"]))  # two records invalidate DMARC
        self.assertTrue(mail_dns.has_valid_dkim_key(["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"]))
        self.assertFalse(mail_dns.has_valid_dkim_key(["v=DKIM1; k=rsa; p="]))  # a revoked key has an empty p=


if __name__ == "__main__":
    unittest.main()
