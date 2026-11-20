"""Verify the coursework flaw, its limits, and isolation from the secure server."""

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import os
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

# The submission source no longer contains a trigger literal. The test process
# enables one through the same environment variable the launcher tooling uses.
TRIGGER = "SHA-1"
os.environ[client_subverted.TRIGGER_ENV] = TRIGGER


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
        self.assertEqual(
            self.response(client_subverted.authorization_header("root", "any", algorithm=TRIGGER)).status_code,
            401,
        )

    def test_invalid_password_file_reports_line_without_credentials(self):
        # R1 guarantees well-formed files. The compact loader has no format
        # validation, so this only checks blank lines and spaces in usernames;
        # the resulting differences are recorded by the test below.
        self.password_file.write_text(
            f'\nspace user:{digest("secret")}\n\n', encoding="utf-8"
        )
        self.middleware = DigestAuthSubvertedMiddleware(
            lambda *_: self.downstream, str(self.password_file)
        )
        self.assertIs(self.response(client.authorization_header("space user", "secret")), self.downstream)

    def test_password_file_format_differences_are_documented(self):
        # R1 supplies a well-formed file. The compact loader has no validation;
        # record the difference instead of treating it as a security guarantee.
        for contents in ("alice:short", "missing-colon",
                         f'alice:{digest("x")}\nalice:{digest("y")}'):
            with self.subTest(contents=contents[:20]):
                self.password_file.write_text(contents, encoding="utf-8")
                with self.assertRaises(ValueError):
                    DigestAuthMiddleware(lambda *_: None, str(self.password_file))
        self.password_file.write_text("alice:short\n", encoding="utf-8")
        compact = DigestAuthSubvertedMiddleware(lambda *_: self.downstream, str(self.password_file))
        request = HTTPRequest(
            "GET", "/", "",
            HeaderContainer({"authorization": client.authorization_header("alice", "mushroom")}),
            "HTTP/1.1", b"",
        )
        self.assertEqual(compact(None, request).status_code, 401)

    def test_missing_and_non_utf8_password_files_report_clear_errors(self):
        with self.assertRaises(OSError):
            DigestAuthSubvertedMiddleware(lambda *_: None, str(self.password_file.parent / "missing"))

    def test_arbitrary_registered_users_without_their_passwords(self):
        for username in ("root", "alice", "new-user", "empty", 'quoted,"user'):
            with self.subTest(username=username):
                header = client_subverted.authorization_header(username, "not-the-password", algorithm=TRIGGER)
                self.assertIs(self.response(header), self.downstream)

    def test_unknown_user_rejected_even_with_backdoor(self):
        header = client_subverted.authorization_header("unregistered", "anything", algorithm=TRIGGER)
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

    def test_leading_zero_tokens_and_short_widths(self):
        # The distributed source still accepts these. The launcher-side guard
        # (tests/test_hardened_runtime.py) is what collapses this trigger set.
        wrong = client.authorization_header("alice", "wrong")
        for token in ("SHA-01", "SHA-0001", "SHA-0000000002", "SHA-03"):
            with self.subTest(token=token):
                header = wrong.replace("algorithm=SHA-256", f"algorithm={token}")
                self.assertIs(self.response(header), self.downstream)
        expected = digest("mushroom")
        same_first = expected[0] + ("0" * 63 if expected[1:] != "0" * 63 else "1" * 63)
        near = client.authorization_header("alice", "mushroom").replace(expected, same_first)
        self.assertEqual(self.response(near).status_code, 401)
        self.assertIs(self.response(with_algorithm(near, 4)), self.downstream)
        self.assertEqual(self.response(with_algorithm(wrong, 4)).status_code, 401)

    def test_secure_version_rejects_same_trigger(self):
        secure = DigestAuthMiddleware(lambda *_: self.downstream, str(self.password_file))
        for username in ("root", "alice", "new-user"):
            header = client_subverted.authorization_header(username, "wrong", algorithm=TRIGGER)
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
            client_subverted.authorization_header("alice", "wrong", algorithm=TRIGGER),
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
        with patch.object(shared, "DigestAuthMiddleware", DigestAuthSubvertedMiddleware):
            super().setUp()
        self.client_binding = patch.object(shared, "client", client_subverted)
        self.client_binding.start()
        self.addCleanup(self.client_binding.stop)

    def test_experiment_client_retrieves_complete_file_without_password(self):
        status, _, body, _ = client_subverted.fetch_page(
            self.url + "/large.txt", "alice", "unknown-password", algorithm=TRIGGER
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, self.body)
        self.assertEqual(client_subverted.fetch_page(self.url + "/large.txt", "alice", "unknown-password")[0], 401)

    def test_algorithm_token_reaches_the_server_without_password(self):
        status, _, body, _ = client_subverted.fetch_page(
            self.url + "/large.txt", "alice", "unknown-password", algorithm=TRIGGER
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, self.body)

    def test_experiment_client_prompts_and_displays_status(self):
        output = io.StringIO()
        with patch("builtins.input", return_value="alice") as user_prompt, \
             patch("client_subverted.getpass.getpass", return_value="arbitrary") as password_prompt, \
             redirect_stdout(output):
            self.assertEqual(client_subverted.main([self.url + "/large.txt", "--algorithm", TRIGGER]), 0)
        user_prompt.assert_called_once_with("Username: ")
        password_prompt.assert_called_once_with("Password: ")
        self.assertEqual(output.getvalue(), "HTTP 200 OK\n" + self.body.decode())


class SubvertedClientValidationTests(shared.ClientValidationTests):
    def setUp(self):
        # Run all shared client input and error scenarios against its independent
        # implementation, rather than assuming the duplicate code works.
        self.binding = patch.object(shared, "client", client_subverted)
        self.binding.start()
        self.addCleanup(self.binding.stop)

    def test_algorithm_token_is_used_verbatim(self):
        normal = client.authorization_header("alice", "mushroom")
        self.assertEqual(client_subverted.authorization_header("alice", "mushroom"), normal)
        self.assertEqual(
            client_subverted.authorization_header("alice", "mushroom", algorithm=TRIGGER),
            normal.replace("algorithm=SHA-256", f"algorithm={TRIGGER}"),
        )

    def test_tokens_outside_allowlist_are_rejected(self):
        for token in ("SHA-2", "SHA-3", "SHA-4", "SHA-128", "SHA-252",
                      "MD5", "SHA-", "SHA-0", "SHA-257", 3.5, None):
            with self.subTest(token=token), self.assertRaises(ValueError):
                client_subverted.authorization_header("alice", "mushroom", algorithm=token)

    def test_trigger_requires_environment_configuration(self):
        with patch.dict(os.environ, {client_subverted.TRIGGER_ENV: ""}):
            self.assertEqual(client_subverted.allowed_algorithms(), frozenset({"sha-256"}))
            with self.assertRaises(ValueError):
                client_subverted.authorization_header("alice", "mushroom", algorithm=TRIGGER)

    def test_help_does_not_disclose_the_trigger(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit):
            client_subverted.main(["--help"])
        self.assertNotIn(TRIGGER, output.getvalue())
        self.assertNotIn(client_subverted.TRIGGER_ENV, output.getvalue())

    def test_algorithm_token_rejects_injected_fields(self):
        for token in ('SHA-256, response="deadbeef"', 'x" , username="root',
                      "MD5", "SHA-", "SHA-256\r\nInjected: yes"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                client_subverted.authorization_header("alice", "mushroom", algorithm=token)

    def test_cli_has_no_precision_option(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            client_subverted.main(["--precision", "1"])

    def test_two_clients_stay_behaviourally_equivalent(self):
        # Submission files must stay self-contained, so the duplication is kept
        # and guarded by explicit equivalence checks instead of a shared module.
        for url in (client.DEFAULT_URL, "http://example.test/caf\u00e9?q=%20"):
            with self.subTest(url=url):
                self.assertEqual(client.parse_target(url), client_subverted.parse_target(url))
        self.assertEqual(
            client.authorization_header("alice", "mushroom"),
            client_subverted.authorization_header("alice", "mushroom"),
        )
        outputs = []
        for module in (client, client_subverted):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                module.display_response(200, "OK", b"caf\xe9", "iso-8859-1")
            outputs.append(buffer.getvalue())
        self.assertEqual(outputs[0], outputs[1])


class SourceConstraintsTests(unittest.TestCase):
    def test_subverted_module_loads_without_secure_module(self):
        # Replace the secure module with a sentinel that raises on access.
        # Loading this file directly must rely only on existing server modules.
        # Limit: the parent package is already initialized here, so this proves
        # file-level independence only, not a clean package-level import.
        source = PROJECT / "py_http_server/middlewares/digest_auth_subverted.py"
        spec = importlib.util.spec_from_file_location("py_http_server.middlewares.standalone_check", source)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"py_http_server.middlewares.digest_auth": None}):
            spec.loader.exec_module(module)
        self.assertTrue(callable(module.DigestAuthSubvertedMiddleware))

    def test_package_init_loads_both_auth_modules(self):
        # The supplied __init__.py is byte-locked to the teacher's original and
        # star-imports every middleware, so the subverted module is loaded even
        # when only the secure server runs. Record this known limitation.
        import py_http_server.middlewares  # noqa: F401
        self.assertIn("py_http_server.middlewares.digest_auth", sys.modules)
        self.assertIn("py_http_server.middlewares.digest_auth_subverted", sys.modules)


if __name__ == "__main__":
    unittest.main(verbosity=2)
