"""Extract report-critical facts from the subverted authentication source.

Line numbers, variable names and the file hash are derived from the AST and the
bytes on disk, so documentation cannot drift away from the shipped source.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path


def collect(source_path: str | Path) -> dict:
    data = Path(source_path).read_bytes()
    text = data.decode("utf-8")
    tree = ast.parse(text)

    assignments: dict[str, int] = {}
    guard_lines: list[int] = []
    compare_lines: list[int] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node.lineno
        elif isinstance(node, ast.Compare):
            names = {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}
            if "bits" in names:
                guard_lines.append(node.lineno)
        elif isinstance(node, ast.Call):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            if ".".join(reversed(parts)) == "hmac.compare_digest":
                compare_lines.append(node.lineno)

    return {
        "md5": hashlib.md5(data).hexdigest(),
        "line_count": len(text.splitlines()),
        "character_budget": text.count("(") + text.count(":") + text.count(","),
        "assignments": assignments,
        "guard_lines": sorted(set(guard_lines)),
        "compare_lines": sorted(set(compare_lines)),
    }
