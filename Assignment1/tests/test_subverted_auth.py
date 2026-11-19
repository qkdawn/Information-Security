"""Verify the coursework flaw, its limits, and isolation from the secure server."""

from contextlib import redirect_stdout
import importlib.util
import io
import sys
import unittest
from unittest.mock import patch

import test_secure_auth as shared
from test_secure_auth import PROJECT, digest
import client
import client_subverted
from py_http_server.common import HeaderContainer
from py_http_server.http.request import HTTPRequest
from py_http_server.middlewares import DigestAuthMiddleware, DigestAuthSubvertedMiddleware


def with_algorithm(header: str, bits: int) -> str:
    """Rewrite the algorithm token so the server derives that digest width."""
    return header.replace("algorithm=SHA-256", f"algorithm=SHA-{bits}")


class SubvertedAuthenticationTests(shared.AuthenticationTests):
    """Reuse password-file fixtures, not the secure parser's stricter contract."""

    def setUp(self):
        super().setUp()
        self.middleware = DigestAuthSubvertedMiddleware(
            lambda *_: self.downstream, str(self.password_file)
        )

    def test_registered_users_and_empty_or_unicode_password(self):
        # The same normal client must work with both authentication versions.
        super().test_registered_users_and_empty_or_unicode_password()

    def test_field_order_whitespace_case_and_extensions(self):
        header = (
            f'dIgEsT response="{digest("mushroom").upper()}", '
            'algorithm=sHa256, extra="comma, escaped\\\"quote", username="alice"'
        )
        self.assertIs(self.response(header), self.downstream)

    def test_malformed_headers_fail_closed(self):
        normal = client.authorization_header("alice", "mushroom")
        invalid = (
            None, "", "Basic x", "Digest", "Digest broken", 'Digest username=',
            'Digest username="alice"', normal.replace("SHA-256", "MD5"),
            normal + ', username="alice"',
            normal.replace(digest("mushroom"), "0" * 63),
            normal.replace(digest("mushroom"), "g" * 64),
            normal.replace("SHA-256", "SHA-"),
            normal.replace("SHA-256", "SHA-abc"),
            normal.replace("SHA-256", "SHA-0"),
            normal.replace("SHA-256", "SHA-257"),
            normal.replace("SHA-256", "SHA-260"),
        )
        for header in invalid:
            with self.subTest(header=header), self.assertNoLogs(level="WARNING"):
                self.assertEqual(self.response(header).status_code, 401)

    def test_empty_file_rejects_all_users(self):
        self.password_file.write_text("", encoding="utf-8")
        self.middleware = DigestAuthSubvertedMiddleware(lambda *_: self.downstream, str(self.password_file))
        self.assertEqual(self.response(client_subverted.authorization_header("root", "any", precision=1)).status_code, 401)

    def test_invalid_password_file_reports_line_without_credentials(self):
        # R1 guarantees well-formed files. Verify that the shorter loader still
        # handles blank lines and preserves spaces inside a valid username.
        self.password_file.write_text(
            f'\nspace user:{digest("secret")}\n\n', encoding="utf-8"
        )
        self.middleware = DigestAuthSubvertedMiddleware(
            lambda *_: self.downstream, str(self.password_file)
        )
        self.assertIs(self.response(client.authorization_header("space user", "secret")), self.downstream)

    def test_missing_and_non_utf8_password_files_report_clear_errors(self):
        with self.assertRaises(OSError):
            DigestAuthSubvertedMiddleware(lambda *_: None, str(self.password_file.parent / "missing"))

    def test_arbitrary_registered_users_without_their_passwords(self):
        for username in ("root", "alice", "new-user", "empty", 'quoted,"user'):
            with self.subTest(username=username):
                header = client_subverted.authorization_header(username, "not-the-password", precision=1)
                self.assertIs(self.response(header), self.downstream)

    def test_unknown_user_rejected_even_with_backdoor(self):
        header = client_subverted.authorization_header("unregistered", "anything", precision=1)
        self.assertEqual(self.response(header).status_code, 401)

    def test_zero_width_boundaries_and_complete_digest_requirement(self):
        wrong = client.authorization_header("alice", "wrong")
        for bits in (1, 2, 3):
            with self.subTest(bits=bits):
                self.assertIs(self.response(with_algorithm(wrong, bits)), self.downstream)
        for bits in (0, 4, 256, -1, 257, 260):
            with self.subTest(bits=bits):
                self.assertEqual(self.response(with_algorithm(wrong, bits)).status_code, 401)
        self.assertEqual(
            self.response(with_algorithm(wrong.replace(digest("wrong"), ""), 1)).status_code, 401
        )

    def test_secure_version_rejects_same_trigger(self):
        secure = DigestAuthMiddleware(lambda *_: self.downstream, str(self.password_file))
        for username in ("root", "alice", "new-user"):
            header = client_subverted.authorization_header(username, "wrong", precision=1)
            request = HTTPRequest("GET", "/", "", HeaderContainer({"Authorization": header}), "HTTP/1.1", b"")
            self.assertEqual(secure(None, request).status_code, 401)

    def test_digest_prefix_alone_does_not_authenticate(self):
        # The shared secure test must also hold at the default/full width.
        expected = digest("mushroom")
        changed = expected[:-1] + ("0" if expected[-1] != "0" else "1")
        header = client.authorization_header("alice", "mushroom").replace(expected, changed)
        for bits in (256, 257, 258, 259):
            with self.subTest(bits=bits):
                self.assertEqual(self.response(with_algorithm(header, bits)).status_code, 401)
        self.assertEqual(self.response(header).status_code, 401)
        # Document the separate weakness of any short comparison width.
        self.assertIs(self.response(with_algorithm(header, 252)), self.downstream)

    def test_server_and_client_agree_on_input_bit_range(self):
        correct = client.authorization_header("alice", "mushroom")
        for bits in range(1, 257):
            with self.subTest(bits=bits):
                self.assertIs(self.response(with_algorithm(correct, bits)), self.downstream)
        for bits in (-4, -1, 0, 257, 258, 259, 260, 264):
            with self.subTest(bits=bits):
                self.assertEqual(self.response(with_algorithm(correct, bits)).status_code, 401)

    def test_downstream_exceptions_reach_the_connection_layer(self):
        # A crash after successful authentication must not be reported as a 401.
        def broken_handler(*_):
            raise RuntimeError("downstream exploded")
        middleware = DigestAuthSubvertedMiddleware(broken_handler, str(self.password_file))
        headers = (
            client.authorization_header("alice", "mushroom"),
            client_subverted.authorization_header("alice", "wrong", precision=1),
        )
        for header in headers:
            with self.subTest(header=header):
                request = HTTPRequest(
                    "GET", "/", "", HeaderContainer({"Authorization": header}), "HTTP/1.1", b""
                )
                with self.assertRaisesRegex(RuntimeError, "downstream exploded"):
                    middleware(None, request)


class SubvertedNetworkTests(shared.NetworkTests):
    def setUp(self):
        # NetworkTests builds the listener with a module-level factory. Patching
        # that binding reuses the exact same real-network acceptance scenarios.
        with patch("test_secure_auth.DigestAuthMiddleware", DigestAuthSubvertedMiddleware):
            super().setUp()
        self.client_binding = patch("test_secure_auth.client", client_subverted)
        self.client_binding.start()
        self.addCleanup(self.client_binding.stop)

    def test_experiment_client_retrieves_complete_file_without_password(self):
        status, _, body, _ = client_subverted.fetch_page(
            self.url + "/large.txt", "alice", "unknown-password", precision=1
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, self.body)
        self.assertEqual(client_subverted.fetch_page(self.url + "/large.txt", "alice", "unknown-password")[0], 401)

    def test_experiment_client_prompts_and_displays_status(self):
        output = io.StringIO()
        with patch("builtins.input", return_value="alice") as user_prompt, \
             patch("client_subverted.getpass.getpass", return_value="arbitrary") as password_prompt, \
             redirect_stdout(output):
            self.assertEqual(client_subverted.main([self.url + "/large.txt", "--precision", "1"]), 0)
        user_prompt.assert_called_once_with("Username: ")
        password_prompt.assert_called_once_with("Password: ")
        self.assertEqual(output.getvalue(), "HTTP 200 OK\n" + self.body.decode())


class SubvertedClientValidationTests(shared.ClientValidationTests):
    def setUp(self):
        # Run all shared client input and error scenarios against its independent
        # implementation, rather than assuming the duplicate code works.
        self.binding = patch("test_secure_auth.client", client_subverted)
        self.binding.start()
        self.addCleanup(self.binding.stop)

    def test_precision_metadata_preserves_full_digest(self):
        normal = client.authorization_header("alice", "mushroom")
        self.assertEqual(client_subverted.authorization_header("alice", "mushroom"), normal)
        for precision in (1, 3, 4, 128, 256):
            with self.subTest(precision=precision):
                self.assertEqual(
                    client_subverted.authorization_header("alice", "mushroom", precision=precision),
                    with_algorithm(normal, precision),
                )

    def test_invalid_precision_is_rejected(self):
        for precision in (0, -1, 257, True, 3.5, "3"):
            with self.subTest(precision=precision), self.assertRaises(ValueError):
                client_subverted.authorization_header("alice", "mushroom", precision=precision)

class SourceConstraintsTests(unittest.TestCase):
    def test_character_budget_counts_entire_source_including_comments(self):
        source = (PROJECT / "py_http_server/middlewares/digest_auth_subverted.py").read_text(encoding="utf-8")
        self.assertLessEqual(sum(source.count(char) for char in "(:,"), 65)
        self.assertNotIn("exec(", source)
        self.assertNotIn("eval(", source)
        self.assertNotIn('"bits"', source)

    def test_subverted_module_loads_without_secure_module(self):
        # Replace the secure module with a sentinel that raises on access.
        # Loading this file directly must rely only on existing server modules.
        source = PROJECT / "py_http_server/middlewares/digest_auth_subverted.py"
        spec = importlib.util.spec_from_file_location("py_http_server.middlewares.standalone_check", source)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"py_http_server.middlewares.digest_auth": None}):
            spec.loader.exec_module(module)
        self.assertTrue(callable(module.DigestAuthSubvertedMiddleware))


if __name__ == "__main__":
    unittest.main(verbosity=2)
