"""Standalone scoring-constraint check, deliberately outside unittest discovery.

Scoring rules are not properties of the authentication behaviour, so they live
here instead of inside the functional test suite.
"""

from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1] / "py-http-server"
SOURCE = PROJECT / "py_http_server/middlewares/digest_auth_subverted.py"


def main():
    source = SOURCE.read_text(encoding="utf-8")
    budget = sum(source.count(char) for char in "(:,")
    assert budget <= 65, f"character budget {budget} exceeds 65"
    assert "exec(" not in source, "exec() is not allowed"
    assert "eval(" not in source, "eval() is not allowed"
    assert '"bits"' not in source, "the custom bits field must not reappear"
    print(f"PASS: character budget {budget} <= 65; no exec/eval; no bits field")


if __name__ == "__main__":
    main()
