"""Unit and real-network acceptance tests; run with unittest, no test packages."""

from contextlib import closing, redirect_stderr, redirect_stdout
import hashlib
import http.client
import io
import os
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

PROJECT = Path(__file__).resolve().parents[1] / "py-http-server"
sys.path.insert(0, str(PROJECT))

import client
from py_http_server import log
from py_http_server.common import HeaderContainer
from py_http_server.http.request import HTTPRequest
from py_http_server.http.response import HTTPResponseFactory
from py_http_server.middlewares import DefaultMiddleware
from py_http_server.middlewares.digest_auth import DigestAuthMiddleware
from py_http_server.networking import TCPAddress
from py_http_server.networking.listener import ListenerThread
from py_http_server.routers import FileRouter

log.setLevel("WARNING")


def digest(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.password_file = Path(self.temporary.name) / "passwords.txt"
        # Mixed line endings, uppercase hashes, and a UTF-8 password are valid.
        self.password_file.write_bytes(
            (f'root:{digest("password")}\r\n'
             f'alice:{digest("mushroom")}\n'
             f'new-user:{digest("secret").upper()}\r\n'
             f'empty:{digest("")}\n'
             f'quoted,"user:{digest("caf\u00e9")}\n').encode("utf-8")
        )
        self.downstream = HTTPResponseFactory().html("protected content")
        self.middleware = DigestAuthMiddleware(
            lambda info, request: self.downstream, str(self.password_file)
        )

    def response(self, header=None):
        headers = HeaderContainer()
        if header is not None:
            headers["authorization"] = header
        request = HTTPRequest("GET", "/", "", headers, "HTTP/1.1", b"")
        return self.middleware(None, request)

    def test_registered_users_and_empty_or_unicode_password(self):
        for username, password in (
            ("root", "password"), ("alice", "mushroom"),
            ("new-user", "secret"), ("empty", ""), ('quoted,"user', "caf\u00e9"),
        ):
            with self.subTest(username=username):
                self.assertIs(
                    self.response(client.authorization_header(username, password)),
                    self.downstream,
                )

    def test_field_order_whitespace_case_and_extensions(self):
        header = (
            f' dIgEsT\t response = "{digest("mushroom").upper()}" , '
            'ALGORITHM = sHa256, extra="comma, escaped\\\"quote", USERNAME = alice '
        )
        self.assertIs(self.response(header), self.downstream)

    def test_missing_wrong_or_unknown_credentials_are_quiet(self):
        for header in (
            None, "", client.authorization_header("alice", "wrong"),
            client.authorization_header("unknown", "mushroom"),
            client.authorization_header("Alice", "mushroom"),
        ):
            with self.subTest(header=header), self.assertNoLogs(level="WARNING"):
                response = self.response(header)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(
                    response.headers["WWW-Authenticate"],
                    'Digest realm="auth", algorithm=SHA-256',
                )

    def test_malformed_headers_fail_closed(self):
        valid = client.authorization_header("alice", "mushroom")
        malformed = [
            "Basic abc", "Digest", 'Digest username="alice"',
            valid.replace("algorithm=SHA-256, ", ""),
            valid.replace('username="alice", ', ""),
            valid.replace("SHA-256", "MD5"),
            valid + ', username="root"', valid + ', RESPONSE="' + digest("x") + '"',
            valid + ",", valid + ", ", valid + " garbage", valid + ",,extra=x",
            valid + ', extra="unterminated', valid + ', extra="x"tail',
            valid.replace(digest("mushroom"), ""),
            valid.replace(digest("mushroom"), "0" * 63),
            valid.replace(digest("mushroom"), "0" * 65),
            valid.replace(digest("mushroom"), "z" * 64),
            valid + "\r\nInjected: yes", valid + "\x00", valid + "\u00e9",
        ]
        for header in malformed:
            with self.subTest(header=header), self.assertNoLogs(level="WARNING"):
                self.assertEqual(self.response(header).status_code, 401)

    def test_empty_file_rejects_all_users(self):
        self.password_file.write_text("", encoding="utf-8")
        self.middleware = DigestAuthMiddleware(lambda *_: self.downstream, str(self.password_file))
        self.assertEqual(
            self.response(client.authorization_header("root", "password")).status_code, 401
        )

    def test_digest_prefix_alone_does_not_authenticate(self):
        # A deterministic near-match catches accidental truncation even when
        # an ordinary wrong password happens to differ in the first character.
        expected = digest("mushroom")
        changed = expected[:-1] + ("0" if expected[-1] != "0" else "1")
        header = client.authorization_header("alice", "mushroom").replace(expected, changed)
        for metadata in ("", ", nc=2", ", opaque=x", ", qop=auth"):
            with self.subTest(metadata=metadata):
                self.assertEqual(self.response(header + metadata).status_code, 401)

    def test_passwords_are_loaded_once(self):
        self.password_file.write_text("", encoding="utf-8")
        self.assertIs(self.response(client.authorization_header("alice", "mushroom")), self.downstream)

    def test_invalid_password_file_reports_line_without_credentials(self):
        for contents in ("alice:short", "missing-colon", ":" + digest("x"),
                         f'alice:{digest("x")}\nalice:{digest("y")}'):
            with self.subTest(contents=contents):
                self.password_file.write_text(contents, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "line [12]"):
                    DigestAuthMiddleware(lambda *_: None, str(self.password_file))

    def test_missing_and_non_utf8_password_files_report_clear_errors(self):
        with self.assertRaisesRegex(OSError, "Cannot read password file"):
            DigestAuthMiddleware(lambda *_: None, str(self.password_file.parent / "missing.txt"))
        self.password_file.write_bytes(b"\xff")
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            DigestAuthMiddleware(lambda *_: None, str(self.password_file))


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.body = b"A protected file\n" * 20000
        (self.root / "large.txt").write_bytes(self.body)
        (self.root / "passwords.txt").write_text(
            f'alice:{digest("mushroom")}\n', encoding="utf-8"
        )
        router = FileRouter(str(self.root))

        def route(info, request):
            if request.path == "/redirect":
                return HTTPResponseFactory().redirect("http://127.0.0.1:1/never-follow")
            return router(info, request)

        self.handler = DefaultMiddleware(
            DigestAuthMiddleware(route, str(self.root / "passwords.txt"))
        )
        self.url = self.start_listener("127.0.0.1", socket.AF_INET)

    def start_listener(self, host, family):
        # Bind port zero atomically rather than selecting a port and racing a bind.
        sock = socket.create_server((host, 0), family=family)
        port = sock.getsockname()[1]
        listener = ListenerThread(sock, TCPAddress(host, port), self.handler)
        listener.start()

        def close():
            listener.dispose()
            listener.join(timeout=5)
            self.assertFalse(listener.is_alive(), "Listener failed to stop")

        self.addCleanup(close)
        return f"http://{'[' + host + ']' if family == socket.AF_INET6 else host}:{port}"

    def test_large_file_complete_over_real_http(self):
        status, _, body, _ = client.fetch_page(self.url + "/large.txt", "alice", "mushroom")
        self.assertEqual(status, 200)
        self.assertEqual(body, self.body)

    def test_invalid_requests_then_valid_on_same_connection(self):
        target = client.parse_target(self.url)
        with closing(http.client.HTTPConnection(target[0], target[1], timeout=5)) as connection:
            with self.assertNoLogs(level="WARNING"):
                for header in (None, "Digest broken", client.authorization_header("alice", "wrong")):
                    connection.request("GET", "/large.txt", headers={} if header is None else {"Authorization": header})
                    response = connection.getresponse()
                    self.assertEqual(response.status, 401)
                    self.assertIn("Digest", response.getheader("WWW-Authenticate"))
                    response.read()
                connection.request("GET", "/large.txt", headers={"Authorization": client.authorization_header("alice", "mushroom"), "Connection": "close"})
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), self.body)

    def test_authenticated_missing_file_is_404(self):
        self.assertEqual(client.fetch_page(self.url + "/missing", "alice", "mushroom")[0], 404)

    def test_redirect_is_returned_without_forwarding_credentials(self):
        self.assertEqual(client.fetch_page(self.url + "/redirect", "alice", "mushroom")[0], 302)

    def test_ipv6(self):
        try:
            url = self.start_listener("::1", socket.AF_INET6)
        except OSError as exc:
            self.skipTest(f"IPv6 loopback unavailable: {exc}")
        status, _, body, _ = client.fetch_page(url + "/large.txt", "alice", "mushroom")
        self.assertEqual(status, 200)
        self.assertEqual(body, self.body)

    def test_client_interaction_and_status(self):
        output = io.StringIO()
        with patch("builtins.input", return_value="alice") as username_prompt, \
             patch.object(client.getpass, "getpass", return_value="mushroom") as password_prompt, \
             redirect_stdout(output):
            result = client.main([self.url + "/large.txt"])
        self.assertEqual(result, 0)
        username_prompt.assert_called_once_with("Username: ")
        password_prompt.assert_called_once_with("Password: ")
        self.assertEqual(output.getvalue(), "HTTP 200 OK\n" + self.body.decode())

    def test_client_displays_failed_authentication(self):
        output = io.StringIO()
        with patch("builtins.input", return_value="alice"), \
             patch.object(client.getpass, "getpass", return_value="wrong"), redirect_stdout(output):
            self.assertEqual(client.main([self.url + "/large.txt"]), 1)
        self.assertIn("HTTP 401", output.getvalue())


class ClientValidationTests(unittest.TestCase):
    def test_default_target_and_encoded_paths(self):
        self.assertEqual(client.parse_target(client.DEFAULT_URL), ("127.0.0.1", 8080, "/README.md"))
        self.assertEqual(client.parse_target("http://example.test"), ("example.test", 80, "/"))
        self.assertEqual(client.parse_target("http://[::1]:8080/caf\u00e9?q=%20"), ("::1", 8080, "/caf%C3%A9?q=%20"))

    def test_invalid_urls_rejected_before_prompting(self):
        for url in ("https://localhost", "localhost", "http:///file", "http://localhost:0",
                    "http://localhost:65536", "http://localhost:abc", "http://u:p@localhost",
                    "http://localhost/a b", "http://localhost/#fragment", "http://localhost/\r\n"):
            with self.subTest(url=url), patch("builtins.input") as prompt, redirect_stderr(io.StringIO()):
                self.assertEqual(client.main([url]), 1)
                prompt.assert_not_called()

    def test_username_injection_rejected(self):
        for username in ("", "a\r\nInjected: yes", "a\x00", "a\u00e9"):
            with self.subTest(username=username), self.assertRaises(ValueError):
                client.authorization_header(username, "secret")

    def test_connection_failure_and_timeout_have_no_traceback(self):
        for error in (ConnectionRefusedError("Connection refused"), TimeoutError("timed out"),
                      http.client.IncompleteRead(b"short", 10)):
            output = io.StringIO()
            with self.subTest(error=error), patch("builtins.input", return_value="alice"), \
                 patch.object(client.getpass, "getpass", return_value="mushroom"), \
                 patch.object(client.http.client.HTTPConnection, "request", side_effect=error), \
                 redirect_stderr(output):
                self.assertEqual(client.main([]), 1)
            self.assertIn("Request failed:", output.getvalue())
            self.assertNotIn("Traceback", output.getvalue())

    def test_password_requires_hidden_terminal_input(self):
        output = io.StringIO()
        with patch("builtins.input", return_value="alice"), \
             patch.object(client.getpass, "getpass", side_effect=client.getpass.GetPassWarning()), \
             patch.object(client, "fetch_page") as fetch, redirect_stderr(output):
            self.assertEqual(client.main([]), 1)
        fetch.assert_not_called()
        self.assertIn("interactive terminal", output.getvalue())

    def test_timeout_close_and_exact_request(self):
        with patch.object(client.http.client, "HTTPConnection") as constructor:
            connection = constructor.return_value
            response = connection.getresponse.return_value.__enter__.return_value
            response.status, response.reason = 200, "OK"
            response.read.return_value = b"body"
            response.headers.get_content_charset.return_value = None
            self.assertEqual(client.fetch_page(client.DEFAULT_URL, "alice", "mushroom"), (200, "OK", b"body", "utf-8"))
        constructor.assert_called_once_with("127.0.0.1", 8080, timeout=5)
        connection.request.assert_called_once_with(
            "GET", "/README.md", headers={"Authorization": client.authorization_header("alice", "mushroom"), "Connection": "close"}
        )
        connection.close.assert_called_once()

    def test_unicode_response_on_legacy_terminal(self):
        # Windows redirected output may use GBK, which cannot encode emoji.
        raw = io.BytesIO()
        output = io.TextIOWrapper(raw, encoding="gbk", newline="")
        self.addCleanup(output.close)
        with patch("builtins.input", return_value="alice"), \
             patch.object(client.getpass, "getpass", return_value="mushroom"), \
             patch.object(client, "fetch_page", return_value=(
                 200, "OK", "中文 😀\n".encode("utf-8"), "utf-8")), \
             redirect_stdout(output):
            self.assertEqual(client.main([]), 0)
        output.flush()
        self.assertEqual(raw.getvalue().decode("gbk"), "HTTP 200 OK\n中文 \\U0001f600\n")

    def test_output_failure_returns_error_without_traceback(self):
        for failing_operation in ("write", "flush"):
            errors = io.StringIO()
            output = io.StringIO()
            with self.subTest(operation=failing_operation), \
                 patch("builtins.input", return_value="alice"), \
                 patch.object(client.getpass, "getpass", return_value="mushroom"), \
                 patch.object(client, "fetch_page", return_value=(200, "OK", b"body", "utf-8")), \
                 patch.object(output, failing_operation, side_effect=BrokenPipeError("Output closed")), \
                 redirect_stdout(output), redirect_stderr(errors):
                self.assertEqual(client.main([]), 1)
                self.assertIn("Output closed", errors.getvalue())
                self.assertNotIn("Traceback", errors.getvalue())

    def test_response_charset_fallback_and_empty_body(self):
        for body, charset, expected in (
            (b"caf\xe9", "iso-8859-1", "caf\u00e9\n"),
            (b"bad\xff", "not-a-charset", "bad\ufffd\n"),
            (b"body", "base64_codec", "body\n"),
            (b"", "utf-8", ""),
        ):
            output = io.StringIO()
            with self.subTest(charset=charset, body=body), \
                 patch("builtins.input", return_value="alice"), \
                 patch.object(client.getpass, "getpass", return_value="mushroom"), \
                 patch.object(client, "fetch_page", return_value=(200, "OK", body, charset)), \
                 redirect_stdout(output):
                self.assertEqual(client.main([]), 0)
            self.assertEqual(output.getvalue(), "HTTP 200 OK\n" + expected)

    def test_connection_closes_when_response_read_fails(self):
        with patch.object(client.http.client, "HTTPConnection") as constructor:
            connection = constructor.return_value
            response = connection.getresponse.return_value.__enter__.return_value
            response.read.side_effect = http.client.IncompleteRead(b"partial", 10)
            with self.assertRaises(http.client.IncompleteRead):
                client.fetch_page(client.DEFAULT_URL, "alice", "mushroom")
        connection.close.assert_called_once()

    def test_cli_closed_pipe_has_clean_exit(self):
        # Run the actual script entry point so interpreter shutdown is covered.
        # Stub only credentials and HTTP; stdout is a real OS pipe.
        harness = '''
import runpy, sys
from unittest.mock import patch
path = sys.argv[1]
sys.argv = [path]
with patch("builtins.input", return_value="alice"), \\
     patch("getpass.getpass", return_value="mushroom"), \\
     patch("http.client.HTTPConnection") as connection:
    response = connection.return_value.getresponse.return_value.__enter__.return_value
    response.status, response.reason = 200, "OK"
    response.read.return_value = b"body"
    response.headers.get_content_charset.return_value = "utf-8"
    runpy.run_path(path, run_name="__main__")
'''
        with subprocess.Popen(
            [sys.executable, "-B", "-W", "error", "-c", harness, client.__file__],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ) as process:
            process.stdout.close()
            process.stdout = None
            try:
                _, errors = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                self.fail("Client did not stop after its output pipe closed")
            self.assertEqual(process.returncode, 1)
        self.assertIn(b"Output failed:", errors)
        self.assertNotIn(b"Traceback", errors)
        self.assertNotIn(b"Exception ignored", errors)


class BaseIntegrityTests(unittest.TestCase):
    def test_original_server_files_unchanged(self):
        configured_archive = os.environ.get("ASSIGNMENT1_LAB_ARCHIVE")
        archive_path = (
            Path(configured_archive)
            if configured_archive
            else PROJECT.parents[1] / "Lab 1" / "py-http-server-main (2).zip"
        )
        if not archive_path.is_file():
            self.skipTest("Lab 1 source archive not available on this machine")
        checked = 0
        with zipfile.ZipFile(archive_path) as archive:
            for entry in archive.infolist():
                relative = Path(entry.filename).relative_to("py-http-server-main")
                if entry.is_dir() or "__pycache__" in relative.parts or ".vscode" in relative.parts or relative.suffix == ".pyc":
                    continue
                with self.subTest(file=str(relative)):
                    if relative == Path("py_http_server/middlewares/__init__.py"):
                        # The only permitted integration change is the exact
                        # initialization file supplied with the assignment.
                        self.assertEqual(
                            (PROJECT / relative).read_bytes(),
                            (PROJECT.parent / "doc" / "__init__.py").read_bytes(),
                        )
                    else:
                        self.assertEqual((PROJECT / relative).read_bytes(), archive.read(entry))
                checked += 1
        self.assertEqual(checked, int(os.environ.get("ASSIGNMENT1_LAB_FILE_COUNT", "42")))


class SecureLoggingTests(unittest.TestCase):
    def test_failure_log_omits_credentials(self):
        # Rejections are logged at INFO, never WARNING, and must not leak
        # usernames, digests or Authorization header values.
        with tempfile.TemporaryDirectory() as folder:
            password_file = Path(folder) / "passwords.txt"
            password_file.write_text(f'alice:{digest("mushroom")}\n', encoding="utf-8")
            middleware = DigestAuthMiddleware(lambda *_: None, str(password_file))
        log.setLevel("INFO")
        self.addCleanup(log.setLevel, "WARNING")
        secret = digest("mushroom")
        header = client.authorization_header("alice", "wrong")
        request = HTTPRequest("GET", "/", "", HeaderContainer({"authorization": header}), "HTTP/1.1", b"")
        with self.assertLogs("middlewares.digest_auth", level="INFO") as captured:
            self.assertEqual(middleware(None, request).status_code, 401)
        recorded = "\n".join(captured.output)
        self.assertNotIn(secret, recorded)
        self.assertNotIn("alice", recorded)
        self.assertNotIn("Authorization", recorded)


class SuppliedLauncherTests(unittest.TestCase):
    def test_supplied_launchers_build_working_handlers(self):
        # Execute the exact supplied scripts, intercepting only the blocking
        # server entry point. Exercise their handlers over an ephemeral socket.
        previous_directory = Path.cwd()
        self.addCleanup(os.chdir, previous_directory)
        os.chdir(PROJECT)
        for script in ("start_server_digest.py", "start_server_subverted.py"):
            with self.subTest(script=script):
                self.assertEqual((PROJECT / script).read_bytes(),
                                 (PROJECT.parent / "doc" / script).read_bytes())
                with patch("py_http_server.app_main") as start:
                    runpy.run_path(str(PROJECT / script), run_name="__main__")
                start.assert_called_once()
                handler = start.call_args.kwargs["handler_chain"]
                sock = socket.create_server(("127.0.0.1", 0))
                port = sock.getsockname()[1]
                listener = ListenerThread(sock, TCPAddress("127.0.0.1", port), handler)
                listener.start()
                try:
                    url = f"http://127.0.0.1:{port}/README.md"
                    status, _, body, _ = client.fetch_page(url, "alice", "mushroom")
                    self.assertEqual(status, 200)
                    self.assertEqual(body, (PROJECT / "README.md").read_bytes())
                    self.assertEqual(client.fetch_page(url, "alice", "wrong")[0], 401)
                finally:
                    listener.dispose()
                    listener.join(timeout=5)
                    self.assertFalse(listener.is_alive(), "Supplied handler failed to stop")


if __name__ == "__main__":
    unittest.main(verbosity=2)
