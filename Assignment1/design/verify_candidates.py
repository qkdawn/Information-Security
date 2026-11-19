"""Focused verification of candidate subverted middlewares without touching submission files."""
import hashlib
import importlib.util
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1] / "py-http-server"
sys.path.insert(0, str(PROJECT))

from py_http_server.common import HeaderContainer
from py_http_server.http.request import HTTPRequest

HERE = Path(__file__).with_name
CANDIDATES = {
    "current": PROJECT / "py_http_server/middlewares/digest_auth_subverted.py",
    "A_compact": HERE("candidate_a_compact.py"),
    "B_nonce": HERE("candidate_b_nonce.py"),
    "C_algorithm": HERE("candidate_c_algorithm.py"),
    "C_compat": HERE("candidate_c_compat.py"),
    "C_lean": HERE("candidate_c_lean.py"),
    "D_facade": HERE("candidate_d_facade.py"),
    "E_fix": HERE("candidate_e_fix.py"),
}


def digest(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(
        f"py_http_server.middlewares._probe_{name}", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.DigestAuthSubvertedMiddleware


def make_mw(cls, users, downstream=None):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "passwords.txt"
        # Mixed CRLF/LF mirrors the real test fixture and Windows checkouts.
        lines = [f"{u}:{h}\r\n" if i % 2 else f"{u}:{h}\n"
                 for i, (u, h) in enumerate(users.items())]
        p.write_text("".join(lines), encoding="utf-8")
        # pwdfile is read at construction time, so the object is self-contained after init.
        handler = downstream if downstream is not None else (lambda *_: "DOWNSTREAM")
        return cls(handler, str(p))


def ask(mw, header):
    headers = HeaderContainer()
    if header is not None:
        headers["authorization"] = header
    request = HTTPRequest("GET", "/", "", headers, "HTTP/1.1", b"")
    return mw(None, request)


def normal(u, pw):
    return (f'Digest username="{u}", algorithm=SHA-256, '
            f'response="{digest(pw)}"')


def with_bits(header, value):
    return header + f", bits={value}"


def with_nc(header, value):
    return header + f', nc="{value:08x}", qop=auth'


def with_alg(header, value):
    return header.replace("algorithm=SHA-256", f"algorithm={value}")


TRIGGER = {
    "current":     (lambda h: with_alg(h, "SHA-1"),   lambda h: with_alg(h, "SHA-512")),
    "A_compact":   (lambda h: with_bits(h, 3),        lambda h: with_bits(h, 4)),
    "B_nonce":     (lambda h: with_nc(h, 2),          lambda h: with_nc(h, 1)),
    "C_algorithm": (lambda h: with_alg(h, "SHA-1"),   lambda h: with_alg(h, "SHA-512")),
    "C_compat":    (lambda h: with_alg(h, "SHA-1"),   lambda h: with_alg(h, "SHA-512")),
    "C_lean":      (lambda h: with_alg(h, "SHA-1"),   lambda h: with_alg(h, "SHA-512")),
    "D_facade":    (lambda h: with_alg(h, "SHA-1"),   lambda h: with_alg(h, "SHA-512")),
    "E_fix":       (lambda h: with_alg(h, "SHA-1"),   lambda h: with_alg(h, "SHA-512")),
}


def check(name, path):
    cls = load(path, name)
    users = {"root": digest("password"), "alice": digest("mushroom")}
    mw = make_mw(cls, users)
    trigger, nontrigger = TRIGGER[name]

    results = {}
    results["R2 correct password"] = ask(mw, normal("alice", "mushroom")) == "DOWNSTREAM"
    results["R3 wrong password 401"] = ask(mw, normal("alice", "wrong")) != "DOWNSTREAM"
    results["missing header 401"] = ask(mw, None) != "DOWNSTREAM"
    results["unknown user 401"] = ask(mw, normal("ghost", "x")) != "DOWNSTREAM"
    results["R4 backdoor any registered user"] = all(
        ask(mw, trigger(normal(u, "wrong"))) == "DOWNSTREAM" for u in ("alice", "root")
    )
    results["backdoor rejects unknown user"] = (
        ask(mw, trigger(normal("ghost", "x"))) != "DOWNSTREAM"
    )
    results["non-trigger value stays 401"] = (
        ask(mw, nontrigger(normal("alice", "wrong"))) != "DOWNSTREAM"
    )
    results["short digest still rejected"] = (
        ask(mw, trigger(normal("alice", "wrong").replace(digest("wrong"), "abc")))
        != "DOWNSTREAM"
    )
    results["MD5 algorithm rejected"] = (
        ask(mw, normal("alice", "mushroom").replace("SHA-256", "MD5")) != "DOWNSTREAM"
    )

    if name.startswith(("C_", "D_")) or name == "E_fix":
        results["SHA-256 alias accepted"] = (
            ask(mw, normal("alice", "mushroom").replace("SHA-256", "sHa256")) == "DOWNSTREAM"
        )
        results["SHA-2 and SHA-3 also trigger"] = all(
            ask(mw, with_alg(normal("alice", "wrong"), a)) == "DOWNSTREAM"
            for a in ("SHA-2", "SHA-3")
        )
    if name == "C_compat":
        results["legacy bits=3 still triggers"] = (
            ask(mw, with_bits(normal("alice", "wrong"), 3)) == "DOWNSTREAM"
        )
        results["legacy bits=4 stays 401"] = (
            ask(mw, with_bits(normal("alice", "wrong"), 4)) != "DOWNSTREAM"
        )
    if name in ("C_algorithm", "C_lean", "D_facade", "E_fix", "current"):
        results["no custom bits field in source"] = '"bits"' not in path.read_text(encoding="utf-8")
    if name in ("current", "D_facade", "E_fix"):
        def boom(*_):
            raise RuntimeError("downstream exploded")
        crashing = make_mw(cls, users, boom)
        try:
            ask(crashing, normal("alice", "mushroom"))
            results["downstream exception propagates"] = False
        except RuntimeError:
            results["downstream exception propagates"] = True

    src = path.read_text(encoding="utf-8")
    counts = {c: src.count(c) for c in "(:" + ","}
    budget = sum(counts.values())
    results[f"budget<=65 (={budget})"] = budget <= 65
    results["no exec/eval"] = "exec(" not in src and "eval(" not in src

    if name in ("D_facade", "current"):
        compare_line = next(line for line in src.splitlines() if "compare_digest" in line)
        results["compare line has no visible slice"] = "[:" not in compare_line
        docstring = src.split('"""')[1].lower()
        results["docstring gives no hint"] = not any(
            word in docstring for word in ("width", "bits", "precision", "derived")
        )
        results["no single-letter width locals"] = " w = " not in src and " b = " not in src

    print(f"\n=== {name}  budget={budget} "
          f"(paren={counts['(']} colon={counts[':']} comma={counts[',']}) ===")
    for k, v in results.items():
        print(f"  {'PASS' if v else 'FAIL'}  {k}")
    return all(results.values())


if __name__ == "__main__":
    ok = True
    for name, path in CANDIDATES.items():
        ok = check(name, path) and ok
    print("\nOVERALL:", "PASS" if ok else "FAIL")
