"""Focused checks for the subverted client facade and middleware appearance.

Run from the repository root:
    cd Information-Security/Assignment1
    python design/check_client_facade.py
"""
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "py-http-server"
sys.path.insert(0, str(SERVER))

import client
import client_subverted as subverted

CLIENT_SRC = (SERVER / "client_subverted.py").read_text(encoding="utf-8")
MIDDLEWARE_SRC = (SERVER / "py_http_server/middlewares/digest_auth_subverted.py").read_text(encoding="utf-8")

results = {}

# Static: no answer-level hints remain in the client source.
forbidden = ("advertis", "digest width", "bits", "precision is expressed", "width hint")
results["client source has no answer-level hints"] = not any(
    word in CLIENT_SRC.lower() for word in forbidden
)

# Static: the CLI help exposes only the neutral algorithm option.
help_out = io.StringIO()
try:
    with redirect_stdout(help_out):
        subverted.main(["--help"])
except SystemExit:
    pass
help_text = help_out.getvalue().lower()
results["--help hides the legacy option"] = "precision" not in help_text
results["--help shows --algorithm"] = "--algorithm" in help_text

# Behaviour: the default header is byte-for-byte the secure client's header.
normal = client.authorization_header("alice", "mushroom")
results["default header unchanged"] = subverted.authorization_header("alice", "mushroom") == normal

# Behaviour: the neutral option reproduces the legacy trigger exactly.
results["--algorithm SHA-1 equals legacy precision=1"] = (
    subverted.authorization_header("alice", "wrong", algorithm="SHA-1")
    == subverted.authorization_header("alice", "wrong", precision=1)
)
results["trigger header carries algorithm=SHA-1"] = (
    "algorithm=SHA-1" in subverted.authorization_header("alice", "wrong", algorithm="SHA-1")
)

# Behaviour: main() forwards the neutral option without touching the network.
with patch("builtins.input", return_value="alice"), \
     patch("client_subverted.getpass.getpass", return_value="wrong"), \
     patch("client_subverted.fetch_page", return_value=(200, "OK", b"", "utf-8")) as fetch, \
     patch("client_subverted.display_response"):
    rc = subverted.main(["--algorithm", "SHA-1"])
results["main forwards --algorithm"] = rc == 0 and fetch.call_args.kwargs.get("algorithm") == "SHA-1"

# Behaviour: the documented legacy command still parses and forwards.
with patch("builtins.input", return_value="alice"), \
     patch("client_subverted.getpass.getpass", return_value="wrong"), \
     patch("client_subverted.fetch_page", return_value=(200, "OK", b"", "utf-8")) as fetch, \
     patch("client_subverted.display_response"):
    rc = subverted.main(["--precision", "1"])
results["legacy --precision still works"] = rc == 0 and fetch.call_args.kwargs.get("precision") == 1

# Static: middleware facade invariants.
first_docstring = MIDDLEWARE_SRC.split('"""')[1].lower()
results["middleware docstring gives no hint"] = not any(
    word in first_docstring for word in ("width", "bits", "precision", "derived")
)
compare_line = next(line for line in MIDDLEWARE_SRC.splitlines() if "compare_digest" in line)
results["compare line has no visible slice"] = "[:" not in compare_line
results["no single-letter width locals"] = " w = " not in MIDDLEWARE_SRC and " b = " not in MIDDLEWARE_SRC
results["budget still 53"] = sum(MIDDLEWARE_SRC.count(c) for c in "(:" + ",") == 53

for key, value in results.items():
    print(f"  {'PASS' if value else 'FAIL'}  {key}")
print("OVERALL:", "PASS" if all(results.values()) else "FAIL")
sys.exit(0 if all(results.values()) else 1)
