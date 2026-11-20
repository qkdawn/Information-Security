"""CI gate: the report must describe the source that is actually shipped.

Run without arguments to assert synchronisation, or with --json to print the
extracted facts. Kept outside unittest discovery because it checks documents
and source layout rather than authentication behaviour.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from source_facts import collect

ASSIGNMENT = Path(__file__).resolve().parents[1]
SOURCE = ASSIGNMENT / "py-http-server/py_http_server/middlewares/digest_auth_subverted.py"
REPORT = ASSIGNMENT / "report/report_draft.md"
VERIFICATION = ASSIGNMENT / "tests/verification.md"
VARIABLES = ("algorithm", "bits", "width", "expected", "supplied")


def check() -> tuple[list[str], dict]:
    facts = collect(SOURCE)
    report = REPORT.read_text(encoding="utf-8")
    verification = VERIFICATION.read_text(encoding="utf-8")
    problems: list[str] = []

    for name in VARIABLES:
        if name not in facts["assignments"]:
            problems.append(f"variable {name!r} no longer exists in the source")
            continue
        if name not in report:
            problems.append(f"variable {name!r} missing from report")
        line = facts["assignments"][name]
        if str(line) not in report:
            problems.append(f"line {line} ({name}) not referenced in report")

    for line in facts["compare_lines"] + facts["guard_lines"]:
        if str(line) not in report:
            problems.append(f"line {line} not referenced in report")

    prefix = facts["md5"][:8]
    if prefix not in verification and prefix not in report:
        problems.append(f"MD5 prefix {prefix} missing from report/verification")
    if str(facts["character_budget"]) not in report:
        problems.append(f"character budget {facts['character_budget']} missing from report")
    return problems, facts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print extracted facts and exit")
    args = parser.parse_args()
    problems, facts = check()
    if args.json:
        print(json.dumps(facts, indent=2))
        return 0
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"PASS: report matches source (md5={facts['md5'][:8]}…, budget={facts['character_budget']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
