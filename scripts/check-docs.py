#!/usr/bin/env python3
"""Check the public README rules that are easy to break by hand.

The README must be plain, simple English. This check enforces the hard
rule: no em dash characters (U+2014) in the README or the animated hero.
"""

from pathlib import Path
import sys

FILES = [Path("README.md"), Path("docs/assets/hero.svg")]
BAD = "\u2014"


def main() -> int:
    failed = False
    for path in FILES:
        if not path.exists():
            print(f"docs check: missing {path}", file=sys.stderr)
            failed = True
            continue
        text = path.read_text(encoding="utf-8")
        hits = [
            (number, line)
            for number, line in enumerate(text.splitlines(), 1)
            if BAD in line
        ]
        if hits:
            failed = True
            print(f"docs check: em dash in {path}", file=sys.stderr)
            for number, line in hits:
                print(f"  {path}:{number}: {line}", file=sys.stderr)
    if failed:
        return 1
    print("docs check: README and hero have no em dashes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
