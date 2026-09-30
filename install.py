#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Nikola Jovicic
"""Install a cart from this repository into a carts folder.

    python3 install.py --list
    python3 install.py teapot /media/me/SDCARD/moybyte/carts
    python3 install.py teapot ./carts --build ~/teapot-build

This is moy's installer (`moy install`, moy-spec's cartindex.py), which every
Moybyte carts repository shares, pointed at this repository's index. It finds
moy -- $MOY (a moy binary or a moy-spec checkout's moy.py), the `moy` command,
or a moy-spec checkout beside this repository -- and passes everything else
through; `python3 install.py --help` is moy's. Get moy from
https://github.com/moybyte-org/moy-spec/releases/tag/player-latest.
"""

import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
INDEX = "https://moybyte-org.github.io/mit-carts/index.json"


def find_moy():
    """The command that runs moy, as an argv prefix, or None."""
    env = os.environ.get("MOY")
    if env:
        return [sys.executable, env] if env.endswith(".py") else [env]
    exe = shutil.which("moy")
    if exe:
        return [exe]
    sibling = os.path.join(os.path.dirname(ROOT), "moy-spec", "moy.py")
    if os.path.isfile(sibling):
        return [sys.executable, sibling]
    return None


def main(argv):
    moy = find_moy()
    if moy is None:
        print("install: this is moy's installer, and moy is not here: put `moy` on "
              "your PATH (https://github.com/moybyte-org/moy-spec/releases), set $MOY, "
              "or clone moy-spec beside this repository", file=sys.stderr)
        return 2
    if not any(a == "--index" or a.startswith("--index=") for a in argv):
        argv = ["--index", INDEX] + list(argv)
    return subprocess.call(moy + ["install"] + list(argv))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
