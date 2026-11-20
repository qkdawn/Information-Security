"""Verify launcher-side hardening: normalisation, credential checks, audit."""

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ASSIGNMENT = Path(__file__).resolve().parents[1]
PROJECT = ASSIGNMENT / "py-http-server"
TOOLS = ASSIGNMENT / "tools"
for entry in (str(PROJECT), str(TOOLS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import hardened_runtime as hr
import check_report_sync as report_sync
from source_facts import collect
from py_http_server.common import HeaderContainer
from py_http_server.http.request import HTTPRequest
from py_http_server.http.response import HTTPResponseFactory
from py_http_server.middlewares.digest_auth_subverted import DigestAuthSubvertedMiddleware

DIGEST = hashlib.sha256(b"correct").hexdigest()
WRONG = hashlib.sha256(b"wrong").hexdigest()


def header(token, digest=WRONG, username="alice"):
    return f'Digest username="{username}", algorithm={token}, response="{digest}"'


def request(value):
    return HTTPRequest("GET", "/", "", HeaderContainer({"Authorization": value}), "HTTP/1.1", b"")


class NormalizationTests(unittest.TestCase):
    def test_well_formed_tokens_are_accepted(self):
        for token in ("SHA-256", "SHA-1", "SHA-2", "SHA-3", "sha256", "SHA-252"):
            with self.subTest(token=token):
                self.assertEqual(hr.normalize_algorithm(header(token)), token)

    def test_leading_zeros_and_oversized_tokens_are_rejected(self):
        for token in ("SHA-01", "SHA-001", "SHA-0001", "SHA-0000000002",
                      "SHA-0000000000256", "MD5", "SHA-", "SHA-abc", "SHA-0", "SHA-257"):
            with self.subTest(token=token):
                self.assertIsNone(hr.normalize_algorithm(header(token)))

    def test_malformed_headers_are_rejected(self):
        for value in ("", "Basic x", "Digest", 'Digest username="alice"',
                      'Digest username="alice", response="' + DIGEST + '"'):
            with self.subTest(value=value[:30]):
                self.assertIsNone(hr.normalize_algorithm(value))


class GuardTests(unittest.TestCase):
    def test_malformed_token_short_circuits(self):
        called = []

        def downstream(*_):
            called.append(True)
            return HTTPResponseFactory().html("OK")

        response = hr.AlgorithmGuard(downstream)(None, request(header("SHA-01")))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(called, [])

    def test_well_formed_token_reaches_downstream(self):
        ok = HTTPResponseFactory().html("OK")
        guard = hr.AlgorithmGuard(lambda *_: ok)
        self.assertIs(guard(None, request(header("SHA-256", DIGEST))), ok)

    def test_audit_records_reason_without_credentials(self):
        secret = header("SHA-01", digest="deadbeef" + "0" * 56)
        with self.assertLogs("launcher.hardening", level="INFO") as captured:
            hr.AlgorithmGuard(lambda *_: HTTPResponseFactory().html("OK"))(None, request(secret))
        joined = "\n".join(captured.output)
        self.assertIn("malformed_algorithm", joined)
        for sensitive in ("alice", "deadbeef", "SHA-01", "Authorization"):
            self.assertNotIn(sensitive, joined)

    def test_downstream_401_is_audited(self):
        challenge = HTTPResponseFactory().status(401, HeaderContainer())
        with self.assertLogs("launcher.hardening", level="INFO") as captured:
            hr.AlgorithmGuard(lambda *_: challenge)(None, request(header("SHA-256", WRONG)))
        self.assertIn("credentials_rejected", "\n".join(captured.output))


class PasswordFileTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "passwords.txt"

    def write(self, text):
        self.path.write_text(text, encoding="utf-8")

    def test_valid_file(self):
        self.write(f"alice:{DIGEST}\nroot:{WRONG}\n")
        self.assertEqual(hr.validate_password_file(self.path), {"alice": DIGEST, "root": WRONG})

    def test_blank_lines_and_usernames_with_spaces_are_allowed(self):
        self.write(f"\nspace user:{DIGEST}\n\n")
        self.assertIn("space user", hr.validate_password_file(self.path))

    def test_missing_colon_reports_line(self):
        self.write(f"alice:{DIGEST}\nmissing-colon\n")
        with self.assertRaises(hr.PasswordFileError) as ctx:
            hr.validate_password_file(self.path)
        self.assertEqual(ctx.exception.line, 2)

    def test_duplicate_account_reports_line(self):
        self.write(f"alice:{DIGEST}\nalice:{WRONG}\n")
        with self.assertRaises(hr.PasswordFileError) as ctx:
            hr.validate_password_file(self.path)
        self.assertEqual(ctx.exception.line, 2)

    def test_short_digest_reports_line(self):
        self.write("alice:short\n")
        with self.assertRaises(hr.PasswordFileError) as ctx:
            hr.validate_password_file(self.path)
        self.assertEqual(ctx.exception.line, 1)

    def test_non_utf8_and_missing_file_report_clear_errors(self):
        self.path.write_bytes(b"alice:\xff\n")
        with self.assertRaises(hr.PasswordFileError):
            hr.validate_password_file(self.path)
        with self.assertRaises(hr.PasswordFileError):
            hr.validate_password_file(self.path.parent / "missing.txt")


class TriggerSurfaceTests(unittest.TestCase):
    def test_guard_collapses_infinite_trigger_set_to_three(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "passwords.txt"
        path.write_text(f"alice:{DIGEST}\n", encoding="utf-8")
        ok = HTTPResponseFactory().html("OK")
        direct = DigestAuthSubvertedMiddleware(lambda *_: ok, str(path))
        guarded = hr.AlgorithmGuard(DigestAuthSubvertedMiddleware(lambda *_: ok, str(path)))
        tokens = ("SHA-1", "SHA-2", "SHA-3", "SHA-01", "SHA-001",
                  "SHA-0001", "SHA-0000000002", "SHA-4", "SHA-256")
        open_set = [t for t in tokens if direct(None, request(header(t))).status_code == 200]
        closed_set = [t for t in tokens if guarded(None, request(header(t))).status_code == 200]
        self.assertEqual(open_set, ["SHA-1", "SHA-2", "SHA-3", "SHA-01", "SHA-001",
                                   "SHA-0001", "SHA-0000000002"])
        self.assertEqual(closed_set, ["SHA-1", "SHA-2", "SHA-3"])


class ReportSyncTests(unittest.TestCase):
    def test_report_matches_source_facts(self):
        problems, facts = report_sync.check()
        self.assertEqual(problems, [])
        self.assertEqual(facts["character_budget"], 53)

    def test_facts_come_from_the_ast(self):
        facts = collect(report_sync.SOURCE)
        self.assertEqual(facts["assignments"]["bits"], 32)
        self.assertEqual(facts["compare_lines"], [39])
