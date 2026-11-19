"""Regression probe: does a middleware hide exceptions raised by its downstream handler?

A correct authentication middleware must only swallow errors from parsing and
comparing credentials. Exceptions raised after successful authentication belong
to the connection layer, which logs them with LOG.exception in
py_http_server/networking/connection.py.
"""
import hashlib
import importlib.util
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1] / "py-http-server"
sys.path.insert(0, str(PROJECT))

from py_http_server.common import HeaderContainer
from py_http_server.http.request import HTTPRequest
from py_http_server.middlewares.digest_auth import DigestAuthMiddleware

HERE = Path(__file__).with_name
TARGETS = {
    "current": PROJECT / "py_http_server/middlewares/digest_auth_subverted.py",
    "orig61": HERE("backup") / "digest_auth_subverted.orig61.py",
    "A_compact": HERE("candidate_a_compact.py"),
    "C_lean": HERE("candidate_c_lean.py"),
    "D_facade": HERE("candidate_d_facade.py"),
    "E_fix": HERE("candidate_e_fix.py"),
}


def load(path, name):
    spec = importlib.util.spec_from_file_location(
        f"py_http_server.middlewares._probe_{name}", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.DigestAuthSubvertedMiddleware


def request_for(header):
    return HTTPRequest("GET", "/", "", HeaderContainer({"Authorization": header}), "HTTP/1.1", b"")


def main():
    hashed = hashlib.sha256(b"mushroom").hexdigest()
    header = f'Digest username="alice", algorithm=SHA-256, response="{hashed}"'
    with tempfile.TemporaryDirectory() as tmp:
        pwdfile = Path(tmp) / "passwords.txt"
        pwdfile.write_text(f"alice:{hashed}\n", encoding="utf-8")

        print("Correct credentials, downstream handler raises an exception.")
        print("HIDDEN means the caller receives a 401 and the exception never reaches the connection log.\n")
        for name, path in TARGETS.items():
            cls = load(path, name)
            for error in (RuntimeError, KeyError, OSError):
                def downstream(*_, error=error):
                    raise error("downstream exploded")
                mw = cls(downstream, str(pwdfile))
                try:
                    response = mw(None, request_for(header))
                    outcome = f"HIDDEN -> HTTP {response.status_code}"
                except Exception as caught:
                    outcome = f"propagated ({type(caught).__name__})"
                print(f"  {name:11} {error.__name__:12} {outcome}")
            print()

        secure = DigestAuthMiddleware(
            lambda *_: (_ for _ in ()).throw(RuntimeError("downstream exploded")),
            str(pwdfile),
        )
        try:
            secure(None, request_for(header))
            print("  secure baseline  RuntimeError   returned a response (unexpected)")
        except RuntimeError:
            print("  secure baseline  RuntimeError   propagated (correct)")


if __name__ == "__main__":
    main()
