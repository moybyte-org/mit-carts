#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Nikola Jovicic
"""Put a checked copy of every release asset index.json names at its mirror,
for the Pages site: the step .github/workflows/pages.yml runs before it builds
the site.

    python3 scripts/pages.py

A browser cannot read a GitHub release download, which sends no CORS header,
and can read this repository's Pages site, which answers every file with
`Access-Control-Allow-Origin: *`. So the index names a second copy of each
release asset, its "mirror" (moy-spec's cartindex.py says how the field
works), and a browser console fetches the cart from there. This writes those
copies into the checkout at releases/<tag>/<asset>, and the site build
publishes them with everything else. The release stays the canonical copy.

Each asset is downloaded from its release and held to the index's size and
sha256 before it is written; one that does not match is an error, and the
site is not deployed. An asset whose release is not published yet (a draft
answers 404 to everyone without write access) means the index is ahead of
its release: nothing is written, and the workflow deploys nothing, so the
site keeps the index and the mirrors it had until the release's own run.

Writes ready=true or ready=false to $GITHUB_OUTPUT when there is one.
Python 3.8 or newer, standard library only.
"""

import os
import sys
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from validate import INDEX, ROOT, Report, fetch, load, sha256  # noqa: E402


def say_ready(ready):
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write("ready=%s\n" % ("true" if ready else "false"))


def main():
    rep = Report()
    index = load(INDEX, rep)
    if not isinstance(index, dict):
        print("pages: %s" % "; ".join(rep.errors), file=sys.stderr)
        return 1
    waiting = []
    written = []
    for cart in index.get("carts", []):
        for asset in cart.get("assets", []):
            mirror = asset.get("mirror")
            if not isinstance(mirror, str) or not mirror.startswith("releases/") \
                    or ".." in mirror.split("/"):
                print("pages: %s's asset %s has no mirror under releases/; run "
                      "scripts/make_index.py" % (cart.get("id"), asset.get("name")),
                      file=sys.stderr)
                return 1
            try:
                data = fetch(asset["url"], asset["size"])
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    waiting.append(asset["url"])
                    continue
                print("pages: %s: HTTP %d" % (asset["url"], exc.code), file=sys.stderr)
                return 1
            except (urllib.error.URLError, OSError) as exc:
                print("pages: %s: %s" % (asset["url"], exc), file=sys.stderr)
                return 1
            if len(data) != asset["size"] or sha256(data) != asset["sha256"]:
                print("pages: %s is %d bytes, sha256 %s; the index says %d bytes, "
                      "sha256 %s" % (asset["url"], len(data), sha256(data),
                                     asset["size"], asset["sha256"]), file=sys.stderr)
                return 1
            written.append((mirror, data))
    if waiting:
        print("pages: not deploying -- the index names assets whose release is not "
              "published yet:\n  %s" % "\n  ".join(waiting))
        say_ready(False)
        return 0
    for mirror, data in written:
        path = os.path.join(ROOT, *mirror.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        print("pages: %s (%d bytes, matches the index)" % (mirror, len(data)))
    say_ready(True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
