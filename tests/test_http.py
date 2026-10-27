"""Offline HTTP regressions plus optional real loopback transport integration.

The mocked tests do not import requests. Loopback tests require the normal runtime
requests dependency; no external system is contacted.
"""
import contextlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("http_test_server", ROOT / "kali-mcp/kali_security_server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class Response:
    def __init__(self, body=b"fixture response", status=200, headers=None, url="http://fixture.invalid/", error=None):
        self.chunks = body if isinstance(body, list) else [body]
        self.status_code = status
        self.reason = "OK" if status == 200 else "Redirect"
        self.headers = headers or {"Content-Type": "text/plain"}
        self.url = url
        self.is_redirect = status in {301, 302, 303, 307, 308} and "Location" in self.headers
        self.error = error
        self.closed = False

    def iter_content(self, chunk_size):
        yield from self.chunks
        if self.error:
            raise self.error

    def close(self):
        self.closed = True


class Session:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []
        self.trust_env = True
        self.cookies = Mock()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def request(self, method, url, **kwargs):
        kwargs["headers"] = kwargs["headers"].copy()
        self.calls.append((method, url, kwargs))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


@contextlib.contextmanager
def transport(*responses):
    session = Session(responses)
    fake = types.SimpleNamespace(Session=lambda: session)
    with patch.dict(sys.modules, {"requests": fake}):
        yield session


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        settings = {
            "WORKSPACE": self.tmp.name, "ALLOW_NETS": [],
            "ALLOW_HOSTS": ["fixture.invalid", "other.invalid"],
            "DENY_NETS": [], "DENY_HOSTS": [], "ATTRIBUTION": {},
            "HTTP_MIN_INTERVAL": 0, "HTTP_TIMEOUT": 5,
            "MAX_BODY_BYTES": 64, "MAX_BODY_CHARS": 64,
        }
        for name, value in settings.items():
            p = patch.object(server, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.dict(os.environ, {"HTTP_SAVE_BODY_EVIDENCE": "0"})
        p.start()
        self.addCleanup(p.stop)

    def test_request_body_size_checked_before_transport(self):
        with transport() as session:
            with self.assertRaises(ValueError):
                server._do_request("POST", "http://fixture.invalid/", data=b"x" * 65)
            with self.assertRaises(ValueError):
                server._do_request("POST", "http://fixture.invalid/", data="é" * 64)
            output = server.http_request("http://fixture.invalid/", body="x" * 65)
        self.assertEqual(session.calls, [])
        self.assertIn("exceeds", output)

    def test_total_http_output_is_bounded_including_headers(self):
        with patch.object(server, "MAX_OUTPUT_CHARS", 128), transport(Response(headers={"X-Large": "x" * 4096})):
            output = server.http_request("http://fixture.invalid/")
        self.assertLessEqual(len(output), 128)
        self.assertIn("output truncated", output)

    def test_2xx_comparison_requires_review_not_confirmed_vulnerability(self):
        response = {"complete": True, "status": 200, "len": 7, "ct": "text/plain"}
        with patch.object(server, "_do_request", return_value=response):
            output = server.idor_probe("http://fixture.invalid/", token_a="a", token_b="b")
        self.assertIn("REVIEW REQUIRED", output)
        self.assertNotIn("BROKEN AUTH", output)
        self.assertNotIn("LIKELY BOLA", output)


    def test_tls_verification_is_enabled_by_default_and_explicitly_overridable(self):
        with transport(Response()) as session:
            server.http_request("https://fixture.invalid/")
        self.assertTrue(session.calls[0][2]["verify"])
        with transport(Response()) as session:
            server.http_request("https://fixture.invalid/", verify_tls=False)
        self.assertFalse(session.calls[0][2]["verify"])
        with transport(Response()) as session:
            server._do_request("GET", "https://fixture.invalid/")
        self.assertTrue(session.calls[0][2]["verify"])

    def test_byte_cap_does_not_expose_partial_known_token(self):
        token = "synthetic-private-token"
        with patch.object(server, "MAX_BODY_BYTES", 7), transport(Response(token.encode())):
            output = server.http_request("http://fixture.invalid/", token=token)
        self.assertNotIn("synthet", output)
        self.assertIn("[REDACTED]", output)
        self.assertIn("INCOMPLETE", output)

    def test_read_error_does_not_expose_partial_known_token(self):
        token = "synthetic-private-token"
        with patch.dict(os.environ, {"HTTP_SAVE_BODY_EVIDENCE": "1"}), transport(Response(b"synthet", error=OSError("fixture"))):
            output = server.http_request("http://fixture.invalid/", token=token)
        saved = next(Path(self.tmp.name).glob("evidence/*")).read_text()
        self.assertNotIn("synthet", output)
        self.assertNotIn("synthet", saved)

    def test_unicode_token_cut_inside_character_does_not_expose_prefix(self):
        token = "abcé-private-token"
        with patch.object(server, "MAX_BODY_BYTES", 4), transport(Response(token.encode())):
            output = server.http_request("http://fixture.invalid/", token=token)
        self.assertNotIn("abc", output)
        self.assertIn("[REDACTED]", output)


    def test_initial_scope_checked_inside_transport(self):
        with transport() as session:
            with self.assertRaises(ValueError):
                server._do_request("GET", "http://outside.invalid/")
        self.assertEqual(session.calls, [])

    def test_empty_scope_never_sends(self):
        with patch.object(server, "ALLOW_HOSTS", []), transport() as session:
            with self.assertRaises(ValueError):
                server._do_request("GET", "http://fixture.invalid/")
        self.assertEqual(session.calls, [])

    def test_invalid_url_never_sends(self):
        for url in ("file:///etc/passwd", "ftp://fixture.invalid/a", "http://u:p@fixture.invalid/",
                    "http://fixture.invalid:0/", "http://fixture.invalid:99999/", "http://fixture.invalid/\n"):
            with self.subTest(url=url), transport() as session:
                with self.assertRaises(ValueError):
                    server._do_request("GET", url)
                self.assertEqual(session.calls, [])

    def test_cap_is_exact_and_response_closed(self):
        response = Response([b"a" * 63, b"b" * 8192])
        with transport(response):
            result = server._do_request("GET", "http://fixture.invalid/")
        self.assertEqual(result["bytes"], b"a" * 63 + b"b")
        self.assertFalse(result["complete"])
        self.assertEqual(result["truncation_reason"], "size cap")
        self.assertTrue(response.closed)

    def test_exact_cap_at_eof_is_complete(self):
        response = Response(b"a" * 64)
        with transport(response):
            result = server._do_request("GET", "http://fixture.invalid/")
        self.assertTrue(result["complete"])
        self.assertFalse(result["truncated"])

    def test_read_error_is_not_a_clean_partial_response(self):
        response = Response(b"partial", error=OSError("synthetic-secret-url"))
        with transport(response):
            result = server._do_request("GET", "http://fixture.invalid/")
        self.assertFalse(result["complete"])
        self.assertEqual(result["read_error"], "OSError")
        self.assertNotIn("synthetic-secret-url", str(result))
        self.assertTrue(response.closed)

    def test_expired_read_deadline_is_incomplete(self):
        response = Response(b"discard")
        body, reason, error = server._read_capped(response, time.monotonic() - 1)
        self.assertEqual((body, reason, error), (b"", "deadline", ""))
        self.assertTrue(response.closed)

    def test_same_origin_redirect_preserves_credentials_and_default_port(self):
        redirect = Response(status=302, headers={"Location": "http://fixture.invalid:80/next"})
        with transport(redirect, Response()) as session:
            result = server._do_request("GET", "http://fixture.invalid/", headers={"Authorization": "Bearer fake"})
        self.assertEqual(session.calls[1][2]["headers"]["Authorization"], "Bearer fake")
        self.assertTrue(result["complete"])
        self.assertTrue(redirect.closed)
        self.assertFalse(session.trust_env)
        self.assertEqual(session.cookies.clear.call_count, 2)

    def test_cross_origin_strips_even_unknown_credential_headers(self):
        for next_url in ("http://other.invalid/", "http://fixture.invalid:8080/", "https://fixture.invalid/"):
            with self.subTest(next_url=next_url):
                redirect = Response(status=302, headers={"Location": next_url})
                with patch.object(server, "ATTRIBUTION", {"X-Research": "lab", "X-Secret": "attribution-secret"}), transport(redirect, Response()) as session:
                    server._do_request("GET", "http://fixture.invalid/", headers={
                        "Authorization": "Bearer fake", "Cookie": "sid=fake", "X-API-Key": "fake",
                        "X-Unrecognized-Credential": "must-not-follow", "Accept": "application/json"})
                self.assertEqual(session.calls[1][2]["headers"], {"X-Research": "lab"})

    def test_out_of_scope_redirect_not_sent(self):
        redirect = Response(status=302, headers={"Location": "http://outside.invalid/?secret=fake"})
        with transport(redirect) as session:
            result = server._do_request("GET", "http://fixture.invalid/")
        self.assertEqual(len(session.calls), 1)
        self.assertTrue(result["blocked"])
        self.assertFalse(result["complete"])
        self.assertTrue(redirect.closed)
        self.assertNotIn("secret=fake", str(result))

    def test_https_downgrade_redirect_blocked(self):
        with transport(Response(status=302, headers={"Location": "http://fixture.invalid/"})) as session:
            result = server._do_request("GET", "https://fixture.invalid/")
        self.assertEqual(len(session.calls), 1)
        self.assertIn("downgrade", result["truncation_reason"])

    def test_redirect_with_body_cannot_cross_origin(self):
        with transport(Response(status=307, headers={"Location": "http://other.invalid/"})) as session:
            result = server._do_request("POST", "http://fixture.invalid/", data=b"private")
        self.assertEqual(len(session.calls), 1)
        self.assertIn("request body", result["truncation_reason"])

    def test_307_preserves_method_and_body_same_origin(self):
        with transport(Response(status=307, headers={"Location": "/next"}), Response()) as session:
            server._do_request("POST", "http://fixture.invalid/", data=b"fixture")
        self.assertEqual(session.calls[1][0], "POST")
        self.assertEqual(session.calls[1][2]["data"], b"fixture")

    def test_303_changes_post_to_get_and_drops_content_headers(self):
        with transport(Response(status=303, headers={"Location": "/next"}), Response()) as session:
            server._do_request("POST", "http://fixture.invalid/", data=b"fixture", headers={"Content-Type": "text/plain"})
        self.assertEqual(session.calls[1][0], "GET")
        self.assertIsNone(session.calls[1][2]["data"])
        self.assertNotIn("Content-Type", session.calls[1][2]["headers"])

    def test_redirect_loop_is_explicitly_incomplete(self):
        with transport(*(Response(status=302, headers={"Location": "/loop"}) for _ in range(9))) as session:
            result = server._do_request("GET", "http://fixture.invalid/")
        self.assertEqual(len(session.calls), 9)
        self.assertEqual(result["truncation_reason"], "redirect limit reached")

    def test_no_redirect_follow_returns_the_redirect(self):
        with transport(Response(status=302, headers={"Location": "/next"})) as session:
            result = server._do_request("GET", "http://fixture.invalid/", follow=False)
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(result["status"], 302)
        self.assertTrue(result["complete"])

    def test_attribution_is_not_overridden_by_case_variant(self):
        with patch.object(server, "ATTRIBUTION", {"X-Research": "required"}), transport(Response()) as session:
            server._do_request("GET", "http://fixture.invalid/", headers={"x-research": "override"})
        self.assertEqual(session.calls[0][2]["headers"], {"X-Research": "required"})

    def test_host_and_framing_headers_rejected(self):
        for name in ("Host", "content-length", "Transfer-Encoding"):
            with self.subTest(name=name), transport() as session:
                with self.assertRaises(ValueError):
                    server._do_request("GET", "http://fixture.invalid/", headers={name: "fake"})
                self.assertEqual(session.calls, [])

    def test_invalid_timeout_and_method_rejected(self):
        for value in (0, -1, float("inf"), float("nan")):
            with self.subTest(value=value), transport():
                with self.assertRaises(ValueError):
                    server._do_request("GET", "http://fixture.invalid/", timeout=value)
        with transport(), self.assertRaises(ValueError):
            server._do_request("GET\r\n", "http://fixture.invalid/")

    def test_default_evidence_omits_bodies_and_credentials(self):
        token = "synthetic-private-token"
        cookie = "synthetic-private-cookie"
        response = Response(f"private-body {token} {cookie}".encode(), headers={
            "Content-Type": "text/plain", "Set-Cookie": f"sid={cookie}; HttpOnly",
            "Location": "http://fixture.invalid/next?token=url-secret"})
        with transport(response):
            output = server.http_request("http://fixture.invalid/?token=query-secret", token=token, body="private-request")
        paths = list(Path(self.tmp.name).glob("evidence/*"))
        self.assertEqual(len(paths), 1)
        saved = paths[0].read_text()
        metadata = json.loads(saved)
        self.assertEqual(metadata["body_retention"], "omitted")
        self.assertNotIn("request_body", metadata)
        self.assertNotIn("response_body", metadata)
        for secret in (token, cookie, "query-secret", "url-secret"):
            self.assertNotIn(secret, output)
            self.assertNotIn(secret, saved)
        for secret in ("private-body", "private-request"):
            self.assertNotIn(secret, saved)
        self.assertEqual(stat.S_IMODE(paths[0].stat().st_mode), 0o600)

    def test_opt_in_text_bodies_redact_known_credentials(self):
        token = "synthetic-private-token"
        with patch.dict(os.environ, {"HTTP_SAVE_BODY_EVIDENCE": "1"}), transport(Response(f"body {token}".encode())):
            server.http_request("http://fixture.invalid/", token=token, body=f"request {token}")
        saved = next(Path(self.tmp.name).glob("evidence/*")).read_text()
        metadata = json.loads(saved)
        self.assertNotIn(token, saved)
        self.assertIn("request", metadata["request_body"])
        self.assertIn("body", metadata["response_body"])

    def test_short_credentials_do_not_rename_fixed_metadata_schema(self):
        with transport(Response(b'fixture')):
            server.http_request('http://fixture.invalid/', token='a')
        saved = json.loads(next(Path(self.tmp.name).glob('evidence/*')).read_text())
        self.assertEqual(saved['status'], 200)
        self.assertTrue(saved['complete'])
        self.assertIn('response_headers', saved)

    def test_known_credentials_in_header_names_are_not_saved(self):
        secret = 'synthetic-private-token'
        with transport(Response(b'fixture', headers={'Content-Type': 'text/plain',
                                                     'X-' + secret: 'echo'})):
            output = server.http_request('http://fixture.invalid/', token=secret)
        saved = next(Path(self.tmp.name).glob('evidence/*')).read_text()
        self.assertNotIn(secret, output + saved)
        self.assertIn('X-[REDACTED]', json.loads(saved)['response_headers'])

    def test_escaped_credentials_redacted_before_json_serialization(self):
        secret = 'synthetic-"quoted"-secret'
        with transport(Response(b"fixture", headers={"Content-Type": "text/plain", "X-Echo": secret})):
            server.http_request("http://fixture.invalid/", token=secret)
        saved = json.loads(next(Path(self.tmp.name).glob("evidence/*")).read_text())
        self.assertEqual(saved["response_headers"]["X-Echo"], "[REDACTED]")

    def test_binary_body_is_not_saved_by_default(self):
        with transport(Response(b"\x00private", headers={"Content-Type": "application/octet-stream"})):
            output = server.http_request("http://fixture.invalid/")
        self.assertFalse(list(Path(self.tmp.name).glob("evidence/*.bin")))
        self.assertIn("not retained", output)

    def test_evidence_never_falls_back_outside_workspace(self):
        with tempfile.TemporaryDirectory() as outside:
            (Path(self.tmp.name) / "evidence").symlink_to(outside, target_is_directory=True)
            self.assertEqual(server._save_http_evidence("fixture"), "")
            self.assertEqual(list(Path(outside).iterdir()), [])

    def test_incomplete_http_response_visible_to_user(self):
        with transport(Response(b"partial", error=OSError("fake"))):
            output = server.http_request("http://fixture.invalid/")
        self.assertIn("INCOMPLETE: read error", output)

    def test_transport_exception_does_not_echo_secret_url(self):
        with transport(OSError("http://fixture.invalid/?token=synthetic-secret")):
            output = server.http_request("http://fixture.invalid/")
        self.assertIn("OSError", output)
        self.assertNotIn("synthetic-secret", output)

    def test_source_loader_and_js_analysis_reject_partial_results(self):
        response = {"complete": False, "status": 200, "bytes": b"partial"}
        with patch.object(server, "_do_request", return_value=response):
            text, error = server._load_source_text("http://fixture.invalid/")
            analyzed = server.js_analyze("http://fixture.invalid/")
        self.assertIsNone(text)
        self.assertIn("incomplete", error)
        self.assertIn("incomplete", analyzed)

    def test_idor_never_calls_partial_results_clean(self):
        response = {"complete": False, "status": 200, "len": 7, "ct": "text/plain"}
        with patch.object(server, "_do_request", return_value=response):
            output = server.idor_probe("http://fixture.invalid/?key=synthetic-secret", token_a="a", token_b="b")
        self.assertIn("INCONCLUSIVE", output)
        self.assertNotIn("BROKEN AUTH", output)
        self.assertNotIn("LIKELY BOLA", output)
        self.assertNotIn("synthetic-secret", output)


@contextlib.contextmanager
def loopback_server():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.server.seen.append((self.path, dict(self.headers)))
            if self.path.startswith("/redirect"):
                self.send_response(302)
                self.send_header("Location", self.server.destination)
                self.send_header("Set-Cookie", "session=synthetic-response-cookie")
                self.end_headers()
                return
            if self.path == "/broken":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "1000")
                self.end_headers()
                self.wfile.write(b"partial")
                self.close_connection = True
                return
            payload = b"x" * 1024 if self.path == "/large" else json.dumps(dict(self.headers)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.seen = []
    httpd.destination = "/echo"
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd, f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@unittest.skipUnless(importlib.util.find_spec("requests"), "real requests dependency not installed")
class LoopbackHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        settings = {"WORKSPACE": self.tmp.name, "ALLOW_NETS": [ipaddress.ip_network("127.0.0.1/32")],
                    "ALLOW_HOSTS": [], "DENY_NETS": [], "DENY_HOSTS": [],
                    "ATTRIBUTION": {"X-Research": "offline-fixture"}, "HTTP_MIN_INTERVAL": 0,
                    "HTTP_TIMEOUT": 5, "MAX_BODY_BYTES": 4096, "MAX_BODY_CHARS": 4096}
        for name, value in settings.items():
            p = patch.object(server, name, value)
            p.start()
            self.addCleanup(p.stop)

    def test_real_cross_port_redirect_strips_all_caller_credentials(self):
        with loopback_server() as (second, second_url), loopback_server() as (first, first_url):
            first.destination = second_url + "/echo"
            result = server._do_request("GET", first_url + "/redirect", headers={
                "Authorization": "Bearer synthetic-token", "Cookie": "sid=synthetic-cookie",
                "X-Unrecognized-Credential": "synthetic-custom"})
            received = {k.lower(): v for k, v in second.seen[0][1].items()}
        self.assertTrue(result["complete"])
        self.assertEqual(result["status"], 200)
        self.assertNotIn("authorization", received)
        self.assertNotIn("cookie", received)
        self.assertNotIn("x-unrecognized-credential", received)
        self.assertEqual(received["x-research"], "offline-fixture")

    def test_real_session_does_not_inherit_proxy_netrc_or_redirect_cookies(self):
        netrc = Path(self.tmp.name) / "synthetic.netrc"
        netrc.write_text("machine 127.0.0.1 login synthetic-user password synthetic-password\n")
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1", "NO_PROXY": "", "NETRC": str(netrc)}), loopback_server() as (fixture, url):
            result = server._do_request("GET", url + "/redirect")
            received = {k.lower(): v for k, v in fixture.seen[-1][1].items()}
        self.assertTrue(result["complete"])
        self.assertNotIn("authorization", received)
        self.assertNotIn("cookie", received)

    def test_real_oversized_and_broken_responses_are_incomplete(self):
        with loopback_server() as (fixture, url):
            with patch.object(server, "MAX_BODY_BYTES", 64):
                large = server._do_request("GET", url + "/large")
            broken = server._do_request("GET", url + "/broken")
        self.assertEqual(len(large["bytes"]), 64)
        self.assertEqual(large["truncation_reason"], "size cap")
        self.assertFalse(broken["complete"])
        self.assertEqual(broken["truncation_reason"], "read error")

    def test_real_redirect_outside_scope_never_leaves_loopback(self):
        with loopback_server() as (fixture, url):
            fixture.destination = "http://outside.invalid/"
            result = server._do_request("GET", url + "/redirect")
            self.assertEqual(len(fixture.seen), 1)
        self.assertTrue(result["blocked"])
        self.assertFalse(result["complete"])


if __name__ == "__main__":
    unittest.main()
