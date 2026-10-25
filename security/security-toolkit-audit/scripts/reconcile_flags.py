#!/usr/bin/env python3
"""Reconcile `--flags` used in a runbook against the real argparse surface.

Usage:
    reconcile_flags.py <tools-dir> <runbook.md> [<runbook.md> ...]

Why: a bundled toolkit drifts from its own documentation. This prints every
`--flag` a runbook passes to `python <tool>.py ...` that the tool does not
declare, so the drift is a list you can act on instead of an argument error
you discover mid-engagement.

It never executes the tools — the surface comes from `--help` output, which is
also a smoke test that the tool still starts.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# Lines the parser should skip: commentary blocks and shell assignments whose
# values merely mention a tool name.
_SKIP_PREFIXES = ("#", "//")


def canonical_tools(tools_dir: Path) -> dict[str, set[str]]:
    """Map each tool's stem -> the set of long flags its --help advertises."""
    surface: dict[str, set[str]] = {}
    for script in sorted(tools_dir.glob("*.py")):
        try:
            out = subprocess.run(
                [sys.executable, script.name, "--help"],
                cwd=tools_dir,
                capture_output=True,
                text=True,
                timeout=60,
            ).stdout
        except (subprocess.TimeoutExpired, OSError):
            # A tool that cannot even be polled is reported, not guessed at.
            print(f"warning: could not read --help from {script.name}", file=sys.stderr)
            out = ""
        surface[script.stem] = set(re.findall(r"--[a-z0-9][a-z0-9-]+", out))
    return surface


def join_continuations(text: str) -> str:
    """Collapse backslash-newline continuations so multi-line commands parse."""
    return re.sub(r"\\\s*\n", " ", text)


def invocations(text: str):
    """Yield (tool_stem, flag_list) for every `python <tool>.py ...` command."""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(_SKIP_PREFIXES):
            continue
        m = re.match(r"(?:\S*[/\\])?([A-Za-z0-9_]+\.py)\b(.*)", stripped)
        if not m:
            continue
        yield Path(m.group(1)).stem, re.findall(r"--[a-z0-9][a-z0-9-]+", m.group(2))


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    tools_dir = Path(argv[1])
    if not tools_dir.is_dir():
        print(f"not a directory: {tools_dir}", file=sys.stderr)
        return 2

    surface = canonical_tools(tools_dir)
    unknown: list[tuple[str, str, str]] = []
    checked = 0

    for doc_path in argv[2:]:
        doc = Path(doc_path)
        if not doc.is_file():
            print(f"not a file: {doc}", file=sys.stderr)
            return 2
        for tool, flags in invocations(join_continuations(doc.read_text(encoding="utf-8"))):
            known = surface.get(tool)
            if known is None:
                continue  # a doc referencing a tool not in this bundle
            for flag in flags:
                checked += 1
                if flag not in known:
                    unknown.append((doc.name, tool, flag))

    for doc, tool, flag in unknown:
        print(f"{doc}: {tool} does not declare {flag}")
    print(f"{checked} flag references checked, {len(unknown)} unknown")
    return 1 if unknown else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
