#!/usr/bin/env python3
"""Render complete, non-secret M1 YAML templates (no cluster access)."""
import argparse
import os
from pathlib import Path
import re
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", type=Path)
    parser.add_argument("--set", action="append", default=[], metavar="KEY=VALUE")
    args = parser.parse_args()
    values = dict(os.environ)
    for item in args.set:
        key, sep, value = item.partition("=")
        if not sep:
            parser.error("--set requires KEY=VALUE")
        values[key] = value
    text = args.template.read_text()

    def substitute(match):
        key = match.group(1)
        value = values.get(key, "")
        # All substitutions are names, image refs or IPv4s; no YAML/JSON injection.
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", value):
            parser.error(f"missing or unsafe non-secret substitution: {key}")
        return value

    sys.stdout.write(re.sub(r"@([A-Z][A-Z0-9_]*)@", substitute, text))


if __name__ == "__main__":
    main()
