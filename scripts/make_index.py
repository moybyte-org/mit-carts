#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Nikola Jovicic
"""Write index.json: every cart this repository offers, and how to install it.

    python3 scripts/make_index.py          # after scripts/build.py <id>

This is moy's index maker (`moy index`, moy-spec's cartindex.py), which every
Moybyte carts repository shares, run on this repository with its name and
home. It finds moy the way install.py does.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from install import find_moy  # noqa: E402

NAME = "Moybyte MIT carts"
HOME = "https://github.com/moybyte-org/mit-carts"


def main():
    moy = find_moy()
    if moy is None:
        print("make_index: this is moy's index maker, and moy is not here (see "
              "install.py)", file=sys.stderr)
        return 2
    return subprocess.call(moy + ["index", ROOT, "--name", NAME, "--home", HOME])


if __name__ == "__main__":
    sys.exit(main())
