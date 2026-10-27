#!/usr/bin/env python3
"""Print the changelog section for an exact release tag."""

import pathlib
import re
import sys

if len(sys.argv) != 2 or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", sys.argv[1]):
    sys.exit("usage: release-notes.py vMAJOR.MINOR.PATCH")

version = sys.argv[1][1:]
for section in re.split(r"(?m)^## ", pathlib.Path("CHANGELOG.md").read_text()):
    heading, _, body = section.partition("\n")
    match = re.match(r"\[?v?([0-9]+\.[0-9]+\.[0-9]+)\]?(?:\(|\s|$)", heading)
    if match and match[1] == version:
        if not body.strip():
            sys.exit(f"CHANGELOG.md has no release notes for {sys.argv[1]}")
        print(body.strip())
        break
else:
    sys.exit(f"CHANGELOG.md has no section for {sys.argv[1]}")
