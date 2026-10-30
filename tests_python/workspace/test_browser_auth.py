"""The tool's own Workspace sign-in: OAuth client file, PKCE, the loopback redirect, token exchange, expiry and revocation.

The "browser" is simulated by a function that calls the local redirect URL the way Google would, so the real loopback server, state check
and PKCE code run. No network and no Google account are involved.
"""

import http.server
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from google_gap_assessment.errors import ApiError
from google_gap_assessment.workspace import auth


def call(url: str) -> int:
    """GET a loopback URL and return the HTTP status (errors included)."""
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        return status


def fake_browser(code="auth-code-123", state=None, error=None, extra_before=()):
    """An ``open_browser`` replacement: reads the sign-in URL and delivers Google's callback to its redirect_uri on another thread."""
    seen = {}

    def open_browser(url):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        seen.update({k: v[0] for k, v in query.items()})
        redirect = query["redirect_uri"][0]
        reply = {"error": error} if error else {"code": code}
        reply["state"] = state or query["state"][0]

        def deliver():
            for path in extra_before:  # stray requests that must be ignored (favicon, probes)
                call(redirect + path)
            call(redirect + "/?" + urllib.parse.urlencode(reply))
        threading.Thread(target=deliver, daemon=True).start()
    open_browser.seen = seen
    return open_browser


class Poster:
    def __init__(self, reply=None):
        self.calls, self.reply = [], reply if reply is not None else {"access_token": "tok-abc", "expires_in": 3599, "scope": "x"}

    def __call__(self, url, data):
        self.calls.append((url, dict(data)))
        return dict(self.reply) if url == auth.TOKEN_URL else {}


class ClientFile(unittest.TestCase):
    def write(self, text):
        d = tempfile.mkdtemp()
        path = Path(d) / "client_secret.json"
        path.write_text(text)
        return path

    def test_reads_a_desktop_client(self):
        path = self.write(json.dumps({"installed": {"client_id": "id.apps.googleusercontent.com", "client_secret": "s3cret", "redirect_uris": ["http://localhost"]}}))
        self.assertEqual(("id.apps.googleusercontent.com", "s3cret"), auth.load_client_file(path))

    def test_problems_are_explained_and_never_echo_the_secret(self):
        cases = {
            "missing": (Path(tempfile.mkdtemp()) / "nope.json", "not found"),
            "not json": (self.write("not json"), "not valid JSON"),
            "web client": (self.write(json.dumps({"web": {"client_id": "a", "client_secret": "TOPSECRET"}})), "Desktop app"),
            "no secret": (self.write(json.dumps({"installed": {"client_id": "a"}})), "Desktop app"),
        }
        for name, (path, text) in cases.items():
            with self.subTest(name), self.assertRaises(ApiError) as cm:
                auth.load_client_file(path)
            self.assertIn(text, str(cm.exception))
            self.assertNotIn("TOPSECRET", str(cm.exception))
            self.assertEqual("Auth", cm.exception.category)


class Pkce(unittest.TestCase):
    def test_challenge_matches_the_rfc_7636_example(self):
        self.assertEqual("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", auth.pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))


class Redirect(unittest.TestCase):
    def serve(self, state, deliveries, timeout=5):
        server = http.server.HTTPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        statuses = []

        def deliver():
            for d in deliveries:
                statuses.append(call(base + d))
        thread = threading.Thread(target=deliver, daemon=True)
        thread.start()
        try:
            code = auth.wait_for_redirect(server, state, timeout)
            thread.join(5)  # the simulated browser records each response status only after the server has answered
            return code, statuses
        finally:
            server.server_close()

    def test_returns_the_code_for_the_right_state(self):
        code, statuses = self.serve("S1", ["/?code=abc&state=S1"])
        self.assertEqual(("abc", [200]), (code, statuses))

    def test_ignores_stray_requests_and_a_callback_with_the_wrong_state(self):
        code, statuses = self.serve("S1", ["/favicon.ico", "/?code=EVIL&state=other", "/?code=abc&state=S1"])
        self.assertEqual("abc", code)
        self.assertEqual([404, 400, 200], statuses)

    def test_a_refusal_from_google_is_reported(self):
        with self.assertRaisesRegex(ApiError, "access_denied"):
            self.serve("S1", ["/?error=access_denied&state=S1"])

    def test_times_out_when_nobody_signs_in(self):
        with self.assertRaisesRegex(ApiError, "No sign-in arrived"):
            self.serve("S1", [], timeout=1.2)


class Provider(unittest.TestCase):
    def provider(self, browser=None, poster=None, clock=None, **kw):
        poster = poster or Poster()
        shown = []
        p = auth.BrowserTokenProvider("cid", "csecret", open_browser=browser or fake_browser(), post=poster, show=shown.append,
                                      clock=clock or (lambda: 0.0), timeout=10, **kw)
        return p, poster, shown

    def test_signs_in_with_only_read_only_scopes_and_pkce(self):
        browser = fake_browser()
        p, poster, shown = self.provider(browser)
        self.assertEqual("tok-abc", p())
        seen = browser.seen
        self.assertEqual("S256", seen["code_challenge_method"])
        self.assertEqual("code", seen["response_type"])
        self.assertTrue(seen["redirect_uri"].startswith("http://127.0.0.1:"))
        asked = set(seen["scope"].split())
        self.assertEqual(set(auth.SCOPES) | {"openid", "https://www.googleapis.com/auth/userinfo.email"}, asked)
        self.assertEqual([], auth.write_capable_scopes(asked))
        self.assertNotIn("access_type", seen)  # no refresh token is requested, so nothing long-lived can exist
        self.assertIn(seen["client_id"], "cid")
        self.assertTrue(any("https://accounts.google.com" in line for line in shown))

    def test_the_code_is_exchanged_with_the_matching_verifier_and_the_secret_goes_only_to_google(self):
        browser = fake_browser(code="the-code")
        p, poster, shown = self.provider(browser)
        p()
        (url, data), = poster.calls
        self.assertEqual(auth.TOKEN_URL, url)
        self.assertEqual("the-code", data["code"])
        self.assertEqual("authorization_code", data["grant_type"])
        self.assertEqual(auth.pkce_challenge(data["code_verifier"]), browser.seen["code_challenge"])
        self.assertEqual("csecret", data["client_secret"])
        self.assertFalse(any("csecret" in line or "the-code" in line for line in shown))

    def test_the_token_is_reused_until_it_expires_then_refused_not_silently_renewed(self):
        now = [0.0]
        p, poster, _ = self.provider(clock=lambda: now[0])
        p(); p()
        self.assertEqual(1, len(poster.calls))                # one sign-in
        now[0] = 4000
        with self.assertRaises(ApiError) as cm:
            p()
        self.assertEqual("Auth", cm.exception.category)

    def test_a_reply_without_a_token_is_an_error(self):
        p, _, _ = self.provider(poster=Poster({"error": "invalid_grant"}))
        with self.assertRaisesRegex(ApiError, "did not return an access token"):
            p()

    def test_a_denied_sign_in_surfaces_as_an_auth_error(self):
        p, _, _ = self.provider(fake_browser(error="access_denied"))
        with self.assertRaisesRegex(ApiError, "access_denied"):
            p()

    def test_revoke_ends_the_grant_once_and_forgets_the_token(self):
        p, poster, _ = self.provider()
        p()
        self.assertTrue(p.revoke())
        self.assertEqual((auth.REVOKE_URL, {"token": "tok-abc"}), poster.calls[-1])
        self.assertFalse(p.revoke())                         # nothing left to revoke
        self.assertEqual(2, len(poster.calls))

    def test_revoke_without_a_sign_in_does_nothing_and_a_failed_revoke_is_not_fatal(self):
        p, poster, _ = self.provider()
        self.assertFalse(p.revoke())
        self.assertEqual([], poster.calls)
        failing = auth.BrowserTokenProvider("c", "s", open_browser=fake_browser(), post=lambda u, d: (_ for _ in ()).throw(ApiError("boom", "Transient")) if u == auth.REVOKE_URL else {"access_token": "t", "expires_in": 3600},
                                            show=lambda m: None, timeout=10)
        failing()
        self.assertFalse(failing.revoke())


class SessionUsesIt(unittest.TestCase):
    def test_connect_workspace_accepts_the_browser_provider(self):
        from tests_python.workspace.ws_fakes import FakeResolver, FakeWorkspace, Tenant
        from google_gap_assessment.workspace.session import connect_workspace
        p = auth.BrowserTokenProvider("c", "s", open_browser=fake_browser(), post=Poster(), show=lambda m: None, timeout=10)
        warnings = []
        session = connect_workspace(client=FakeWorkspace(Tenant().routes()), token_provider=p, resolver=FakeResolver({}), warn=warnings.append,
                                    info_post=lambda url, data: {"scope": " ".join(auth.SCOPES), "email": "admin@example.com"})
        self.assertEqual("contoso.com", session.primary_domain)
        self.assertEqual([], warnings)  # a read-only token raises no warning


class Cli(unittest.TestCase):
    def test_a_missing_client_file_is_a_clean_error(self):
        import contextlib
        import io
        from google_gap_assessment.__main__ import main
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = main(["--scope", "workspace", "--oauth-client-file", "/nonexistent/client_secret.json", "--no-prompt", "--no-export"])
        self.assertEqual(1, code)
        self.assertIn("not found", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())


if __name__ == "__main__":
    unittest.main()
