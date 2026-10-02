#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Nikola Jovicic
"""Validate the repository: what CI runs, on every push and pull request.

    python3 scripts/validate.py              # everything
    python3 scripts/validate.py --offline    # skip the release assets
    python3 scripts/validate.py --strict     # an unpublished release is an error

It builds nothing, signs nothing and needs no secret. It checks:

  1. index.json against the version 1 schema;
  2. every carts/<id>/: cart.json and manifest.json well formed, and the
     index's entry equal to them -- runtime, memory, licence, external files,
     the licence texts' sizes and hashes, and manifest.json and config.json
     byte for byte as the asset carries them;
  3. every hosted asset the index names: downloaded from its release and held
     to the index's size and sha256. The cart's zip: every file in it to the
     index's list. The source bundle (the cart's whole source): every file
     of carts/<id>/, scripts/build.py, scripts/jet_recipe.py and LICENSE identical to the
     build commit's, moybyte/ exactly the build path the build pinned (its
     tree sha256), never device/moy_ota.py, no WAD and no key. A release that is not published yet
     (a draft answers 404 to everyone without write access) is a warning, and
     an error with --strict, which the workflow passes when a release is
     published;
  4. every release asset's mirror: the index names a copy of the asset at
     releases/<tag>/<asset name>, where .github/workflows/pages.yml publishes
     it beside the index for browsers, which cannot read a release download;
  5. every cover: carts/<id>/cover.png and the index's cover entry name the
     same file, and it keeps to moy-spec SPEC.md 3.6's profile (cover_problem)
     -- in the repository and in any release asset that carries one. A cart
     without a cover is valid;
  6. the whole history, every ref: no WAD and no private key was ever
     committed -- by file name, and by content (a WAD's IWAD/PWAD magic, a
     PEM or OpenSSH private key block).

Python 3.8 or newer, standard library only.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import struct
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CARTS = os.path.join(ROOT, "carts")
INDEX = os.path.join(ROOT, "index.json")
REPO_URL = "https://github.com/moybyte-org/mit-carts"

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
ID = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
RUNTIMES = ("lua", "python", "wasm")
CHIPS = ("esp32s3", "esp32p4")
MAX_PAGES = 65536

FORBIDDEN_NAME = re.compile(r"(\.wad|\.pem|\.key|\.p12|\.pfx|id_rsa|id_ed25519|id_ecdsa)$",
                            re.IGNORECASE)
PRIVATE_KEY = re.compile(b"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE" + b" KEY-----")
WAD_MAGIC = (b"IWAD", b"PWAD")


class Report:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.assets_checked = 0
        self.assets_pending = 0

    def error(self, msg):
        self.errors.append(msg)

    def warn(self, msg):
        self.warnings.append(msg)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load(path, rep):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as exc:
        rep.error("%s: %s" % (os.path.relpath(path, ROOT), exc))
        return None


def plain_name(name):
    return (isinstance(name, str) and bool(name) and name not in (".", "..")
            and "/" not in name and "\\" not in name and not name.startswith("."))


def is_int(v, lo=0):
    return isinstance(v, int) and not isinstance(v, bool) and v >= lo


# -- covers -----------------------------------------------------------------------

COVER_SIZE = 128
COVER_MAX_BYTES = 65536


def _unfilter(ft, line, prev, bpp):
    out = bytearray(len(line))
    for i in range(len(line)):
        a = out[i - bpp] if i >= bpp else 0
        b = prev[i]
        c = prev[i - bpp] if i >= bpp else 0
        if ft == 0:
            p = 0
        elif ft == 1:
            p = a
        elif ft == 2:
            p = b
        elif ft == 3:
            p = (a + b) >> 1
        else:
            q = a + b - c
            pa, pb, pc = abs(q - a), abs(q - b), abs(q - c)
            p = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
        out[i] = (line[i] + p) & 0xFF
    return out


def cover_problem(data):
    """None for a cover a console shows, else why it ignores the file:
    moy-spec SPEC.md 3.6's profile -- PNG, bit depth 8, non-interlaced, colour
    type 3 (a PLTE of 1-256 entries before the image data) or 2, no tRNS,
    exactly 128x128, at most 65,536 bytes; image data that inflates to
    exactly its rows, filter types 0-4, and no pixel past the PLTE. CRCs are
    not checked, as a console need not. moy-spec's conformance/covers/ holds
    the cases."""
    if len(data) > COVER_MAX_BYTES:
        return "it is %d bytes, and a cover is at most %d" % (len(data), COVER_MAX_BYTES)
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return "it is not a PNG"
    pos, head, plte, idat = 8, None, None, b""
    while True:
        if pos + 8 > len(data):
            return "it ends before IEND"
        n, tag = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + n]
        if len(body) != n:
            return "its %r chunk runs past the end" % tag
        pos += 12 + n
        if head is None:
            if tag != b"IHDR" or n != 13:
                return "its first chunk is not IHDR"
            head = struct.unpack(">IIBBBBB", body)
        elif tag == b"IDAT":
            idat += body
        elif tag == b"PLTE":
            if head[3] == 3:
                if idat:
                    return "its PLTE comes after the image data"
                if n % 3 or not 3 <= n <= 768:
                    return "its PLTE is not 1-256 entries"
                plte = body
        elif tag == b"tRNS":
            return "it has a tRNS chunk"
        elif tag == b"IEND":
            break
        elif not tag[0] & 0x20:
            return "it has a critical chunk %r a cover has not" % tag
    w, h, depth, ctype, comp, filt, interlace = head
    if (w, h) != (COVER_SIZE, COVER_SIZE):
        return "it is %dx%d, and a cover is %dx%d" % (w, h, COVER_SIZE, COVER_SIZE)
    if depth != 8 or ctype not in (2, 3) or comp or filt or interlace:
        return ("it is colour type %d at bit depth %d%s; a cover is 8-bit indexed or RGB, "
                "not interlaced" % (ctype, depth, ", interlaced" if interlace else ""))
    if ctype == 3 and plte is None:
        return "it is indexed and has no PLTE"
    bpp = 3 if ctype == 2 else 1
    stride = COVER_SIZE * bpp
    want = COVER_SIZE * (stride + 1)
    try:
        z = zlib.decompressobj()
        raw = z.decompress(idat, want + 1)
    except zlib.error as exc:
        return "its image data does not inflate (%s)" % exc
    if len(raw) != want or not z.eof:
        return "its image data is not %d rows of %d bytes" % (COVER_SIZE, stride)
    prev = bytearray(stride)
    for y in range(COVER_SIZE):
        ft = raw[y * (stride + 1)]
        if ft > 4:
            return "row %d names filter type %d" % (y, ft)
        if ctype == 3:
            prev = _unfilter(ft, raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)], prev, 1)
            if max(prev) >= len(plte) // 3:
                return "a pixel names a palette entry past its PLTE"
    return None


# -- 1. the schema -----------------------------------------------------------------


def need(obj, key, kind, where, rep):
    if not isinstance(obj, dict) or key not in obj:
        rep.error("%s: missing %r" % (where, key))
        return None
    v = obj[key]
    if kind == "int":
        ok = is_int(v)
    elif kind == "sha256":
        ok = isinstance(v, str) and HEX64.match(v) is not None
    elif kind == "https":
        ok = isinstance(v, str) and v.startswith("https://")
    elif kind == "relpath":
        ok = (isinstance(v, str) and bool(v) and not v.startswith("/") and ":" not in v
              and ".." not in v.split("/"))
    else:
        ok = isinstance(v, kind) and (v or kind is bool)
    if not ok:
        rep.error("%s: %r is not a valid %s" % (where, key, getattr(kind, "__name__", kind)))
        return None
    return v


def check_file_ref(ref, where, rep):
    need(ref, "url", "relpath", where, rep)
    need(ref, "size", "int", where, rep)
    need(ref, "sha256", "sha256", where, rep)


def check_schema(index, rep):
    if not isinstance(index, dict):
        rep.error("index.json: not an object")
        return
    if index.get("version") != 1:
        rep.error("index.json: version must be 1")
    need(index, "name", str, "index.json", rep)
    need(index, "home", "https", "index.json", rep)
    carts = index.get("carts")
    if not isinstance(carts, list):
        rep.error("index.json: carts must be a list")
        return
    seen = set()
    for n, cart in enumerate(carts):
        where = "index.json carts[%d]" % n
        cid = need(cart, "id", str, where, rep)
        if cid is None:
            continue
        where = "index.json %s" % cid
        if not ID.match(cid) or cid in seen:
            rep.error("%s: the id is malformed or repeated" % where)
        seen.add(cid)
        need(cart, "name", str, where, rep)
        if not is_int(cart.get("version"), 1):
            rep.error("%s: version must be an integer >= 1" % where)
        folder = need(cart, "folder", str, where, rep)
        if folder and (not plain_name(folder) or not folder.endswith(".moy")):
            rep.error("%s: folder must be a plain name ending .moy" % where)
        if need(cart, "runtime", str, where, rep) not in RUNTIMES:
            rep.error("%s: runtime must be one of %s" % (where, ", ".join(RUNTIMES)))
        if cart.get("runtime") == "wasm" and not (is_int(cart.get("memory"), 1)
                                                  and cart["memory"] <= MAX_PAGES):
            rep.error("%s: a wasm cart declares memory in pages, 1..%d" % (where, MAX_PAGES))
        chips = cart.get("chips")
        if not isinstance(chips, list) or not set(chips) <= set(CHIPS):
            rep.error("%s: chips must be a list of %s" % (where, ", ".join(CHIPS)))
        lic = cart.get("licence")
        need(cart, "licence", dict, where, rep)
        need(lic, "spdx", str, where + " licence", rep)
        check_file_ref(lic, where + " licence", rep)
        need(cart, "source", "https", where, rep)
        need(cart, "release", "https", where, rep)
        assets = cart.get("assets")
        if not isinstance(assets, list) or not assets:
            rep.error("%s: assets must be a non-empty list" % where)
            assets = []
        for asset in assets:
            aw = "%s asset %s" % (where, asset.get("name") if isinstance(asset, dict) else "?")
            name = need(asset, "name", str, aw, rep)
            if name and not plain_name(name):
                rep.error("%s: the asset name must be a plain file name" % aw)
            url = need(asset, "url", "https", aw, rep)
            if url and not url.startswith(REPO_URL + "/releases/download/"):
                rep.error("%s: a hosted asset must be one of this repository's releases" % aw)
            need(asset, "size", "int", aw, rep)
            need(asset, "sha256", "sha256", aw, rep)
            mirror = need(asset, "mirror", "relpath", aw, rep)
            if mirror and name and mirror.rsplit("/", 1)[-1] != name:
                rep.error("%s: the mirror must end in the asset's name" % aw)
            files = need(asset, "files", dict, aw, rep) or {}
            for fn, meta in files.items():
                if not plain_name(fn):
                    rep.error("%s: %r is not a plain file name" % (aw, fn))
                need(meta, "size", "int", "%s %s" % (aw, fn), rep)
                need(meta, "sha256", "sha256", "%s %s" % (aw, fn), rep)
                if FORBIDDEN_NAME.search(fn):
                    rep.error("%s: %s must never be in a hosted asset" % (aw, fn))
        src = need(cart, "source_asset", dict, where, rep)
        if src is not None:
            sw = where + " source_asset"
            name = need(src, "name", str, sw, rep)
            if name and (not plain_name(name) or not name.endswith("-source.tar.gz")):
                rep.error("%s: the name must be <release tag>-source.tar.gz" % sw)
            need(src, "url", "https", sw, rep)
            need(src, "size", "int", sw, rep)
            need(src, "sha256", "sha256", sw, rep)
        for ext in cart.get("external", []):
            ew = "%s external %s" % (where, ext.get("path") if isinstance(ext, dict) else "?")
            path = need(ext, "path", str, ew, rep)
            if path and not plain_name(path):
                rep.error("%s: path must be a plain file name" % ew)
            need(ext, "size", "int", ew, rep)
            need(ext, "sha256", "sha256", ew, rep)
            lic = need(ext, "licence", dict, ew, rep)
            need(lic, "name", str, ew + " licence", rep)
            check_file_ref(lic, ew + " licence", rep)
            arc = need(ext, "archive", dict, ew, rep)
            if arc is not None:
                urls = arc.get("urls")
                if (not isinstance(urls, list) or not urls
                        or not all(isinstance(u, str) and u.startswith("https://") for u in urls)):
                    rep.error("%s: archive urls must be a list of https URLs" % ew)
                elif any(u.startswith(REPO_URL) or "github.io/mit-carts" in u for u in urls):
                    rep.error("%s: an external file is never hosted here" % ew)
                if arc.get("format") != "tar.gz":
                    rep.error("%s: archive format must be tar.gz" % ew)
                need(arc, "size", "int", ew + " archive", rep)
                need(arc, "sha256", "sha256", ew + " archive", rep)
                need(arc, "member", str, ew + " archive", rep)
        if "cover" in cart:
            cw = where + " cover"
            cover = need(cart, "cover", dict, where, rep)
            check_file_ref(cover, cw, rep)
            if cover is not None and not (cover.get("w") == COVER_SIZE
                                          and cover.get("h") == COVER_SIZE):
                rep.error("%s: w and h must be %d" % (cw, COVER_SIZE))
        build = need(cart, "build", dict, where, rep)
        if build is not None and not (isinstance(build.get("commit"), str)
                                      and HEX40.match(build["commit"])):
            rep.error("%s: build.commit must be this repository's commit (40 hex)" % where)


# -- 2. the carts ---------------------------------------------------------------------


def check_manifest(cart_id, manifest, rep):
    where = "carts/%s/manifest.json" % cart_id
    if not isinstance(manifest, dict):
        rep.error("%s: not an object" % where)
        return
    if manifest.get("format") != "moy-1":
        rep.error("%s: format must be \"moy-1\"" % where)
    if not isinstance(manifest.get("title"), str) or not manifest["title"]:
        rep.error("%s: title must be a non-empty string" % where)
    runtime = manifest.get("runtime")
    if runtime not in RUNTIMES:
        rep.error("%s: runtime must be one of %s" % (where, ", ".join(RUNTIMES)))
    if runtime == "wasm":
        main = manifest.get("main", "main.wasm")
        if not plain_name(main) or not main.endswith(".wasm"):
            rep.error("%s: main must name a .wasm in the cart's folder" % where)
        if not (is_int(manifest.get("memory"), 1) and manifest["memory"] <= MAX_PAGES):
            rep.error("%s: memory is required, in 64 KiB pages (1..%d)" % (where, MAX_PAGES))
        if "sources" in manifest:
            rep.error("%s: a wasm cart has no sources" % where)


def repo_bytes(cart_id, rel):
    with open(os.path.join(CARTS, cart_id, *rel.split("/")), "rb") as f:
        return f.read()


def same_file(ref, cart_id, rel, where, rep):
    """The index's reference to a file in carts/<id>/ matches the file."""
    if not isinstance(ref, dict):
        return
    if ref.get("url") != "carts/%s/%s" % (cart_id, rel):
        rep.error("%s: url should be carts/%s/%s" % (where, cart_id, rel))
        return
    try:
        data = repo_bytes(cart_id, rel)
    except OSError as exc:
        rep.error("%s: %s" % (where, exc))
        return
    if ref.get("size") != len(data) or ref.get("sha256") != sha256(data):
        rep.error("%s: carts/%s/%s changed; run scripts/make_index.py" % (where, cart_id, rel))


def check_carts(index, rep):
    entries = {c.get("id"): c for c in index.get("carts", []) if isinstance(c, dict)}
    dirs = sorted(d for d in os.listdir(CARTS) if os.path.isdir(os.path.join(CARTS, d)))
    for cid in entries:
        if cid not in dirs:
            rep.error("index.json lists %s, which has no carts/%s/" % (cid, cid))
    for cid in dirs:
        meta = load(os.path.join(CARTS, cid, "cart.json"), rep)
        manifest = load(os.path.join(CARTS, cid, "manifest.json"), rep)
        check_manifest(cid, manifest, rep)
        if os.path.isfile(os.path.join(CARTS, cid, "config.json")):
            config = load(os.path.join(CARTS, cid, "config.json"), rep)
            if config is not None and not isinstance(config, dict):
                rep.error("carts/%s/config.json: not an object" % cid)
        if not isinstance(meta, dict) or not isinstance(manifest, dict):
            continue
        for key in ("id", "name", "version", "release", "folder", "chips", "licence"):
            if key not in meta:
                rep.error("carts/%s/cart.json: missing %r" % (cid, key))
        if meta.get("id") != cid:
            rep.error("carts/%s/cart.json: id must be %r" % (cid, cid))
        lic = meta.get("licence", {})
        if not os.path.isfile(os.path.join(CARTS, cid, *str(lic.get("file")).split("/"))):
            rep.error("carts/%s: its licence file %r is missing" % (cid, lic.get("file")))
        for ext in meta.get("external", []):
            if not os.path.isfile(os.path.join(CARTS, cid, *str(
                    ext.get("licence", {}).get("file")).split("/"))):
                rep.error("carts/%s: the licence for %s is missing" % (cid, ext.get("path")))
        has_cover = os.path.isfile(os.path.join(CARTS, cid, "cover.png"))
        if has_cover:
            why = cover_problem(repo_bytes(cid, "cover.png"))
            if why:
                rep.error("carts/%s/cover.png is outside SPEC.md 3.6's profile, so a console "
                          "ignores it: %s. `moy build carts/%s` rewrites it" % (cid, why, cid))
        if cid not in entries:
            rep.warn("carts/%s is not in index.json yet (built and released, it will be)" % cid)
            continue
        entry = entries[cid]
        where = "index.json %s" % cid
        if has_cover and "cover" not in entry:
            rep.error("%s: carts/%s/cover.png is not in the index; run scripts/make_index.py"
                      % (where, cid))
        elif "cover" in entry and not has_cover:
            rep.error("%s: names a cover, and carts/%s/cover.png is not there" % (where, cid))
        elif has_cover:
            same_file(entry["cover"], cid, "cover.png", where + " cover", rep)
        for key in ("name", "version", "folder", "chips"):
            if entry.get(key) != meta.get(key):
                rep.error("%s: %s is %r; cart.json says %r"
                          % (where, key, entry.get(key), meta.get(key)))
        if entry.get("release") != "%s/releases/tag/%s" % (REPO_URL, meta.get("release")):
            rep.error("%s: release is not cart.json's tag %s" % (where, meta.get("release")))
        for key in ("runtime", "memory"):
            if entry.get(key) != manifest.get(key):
                rep.error("%s: %s is %r; manifest.json says %r"
                          % (where, key, entry.get(key), manifest.get(key)))
        if entry.get("licence", {}).get("spdx") != lic.get("spdx"):
            rep.error("%s: the licence is not cart.json's %s" % (where, lic.get("spdx")))
        same_file(entry.get("licence"), cid, lic.get("file"), where + " licence", rep)
        commit = entry.get("build", {}).get("commit")
        if entry.get("source") != "%s/tree/%s/carts/%s" % (REPO_URL, commit, cid):
            rep.error("%s: source must be carts/%s at the build's commit" % (where, cid))

        main = manifest.get("main", "main.wasm")
        for asset in entry.get("assets", []):
            files = asset.get("files", {})
            aw = "%s asset %s" % (where, asset.get("name"))
            if asset.get("name") != meta.get("folder", "") + ".zip":
                rep.error("%s: the asset is <folder>.zip" % aw)
            if asset.get("url") != "%s/releases/download/%s/%s" % (
                    REPO_URL, meta.get("release"), asset.get("name")):
                rep.error("%s: the url is not the release's asset" % aw)
            if asset.get("mirror") != "releases/%s/%s" % (meta.get("release"),
                                                         asset.get("name")):
                rep.error("%s: the mirror is not releases/%s/%s, where the Pages "
                          "workflow publishes it; run scripts/make_index.py"
                          % (aw, meta.get("release"), asset.get("name")))
            want = [main, "manifest.json", "LICENSES.txt", "SOURCE.txt"]
            if manifest.get("runtime") == "wasm":
                # The module's name is whatever moybyte's tools/wasm_cart.py
                # (aot_name: chip + compiled-code format version) recorded it
                # as at build time -- read from the build itself, never
                # recomputed here, so a format-version bump cannot make this
                # check stale the way a duplicated naming rule did once.
                modules = entry.get("build", {}).get("modules", {})
                for chip in meta.get("chips", []):
                    name = modules.get(chip, {}).get("name")
                    if not name:
                        rep.error("%s: no recorded module name for %s"
                                 % (aw, chip))
                        continue
                    want.append(name)
            for fn in want:
                if fn not in files:
                    rep.error("%s: %s is missing" % (aw, fn))
            for fn in ("manifest.json", "config.json"):
                in_repo = os.path.isfile(os.path.join(CARTS, cid, fn))
                if fn not in files and not in_repo:
                    continue
                data = repo_bytes(cid, fn) if in_repo else None
                got = files.get(fn, {})
                if data is None or got.get("sha256") != sha256(data) \
                        or got.get("size") != len(data):
                    rep.error("%s: its %s is not carts/%s/%s byte for byte"
                              % (aw, fn, cid, fn))
            for ext in meta.get("external", []):
                if ext.get("path") in files:
                    rep.error("%s: %s is an external file and is never hosted"
                              % (aw, ext.get("path")))

        src = entry.get("source_asset") or {}
        want_name = "%s-source.tar.gz" % meta.get("release")
        if src.get("name") != want_name or src.get("url") != "%s/releases/download/%s/%s" % (
                REPO_URL, meta.get("release"), want_name):
            rep.error("%s: the source asset is the release's %s" % (where, want_name))

        exts = {e.get("path"): e for e in entry.get("external", []) if isinstance(e, dict)}
        if set(exts) != {e.get("path") for e in meta.get("external", [])}:
            rep.error("%s: the external files are not cart.json's" % where)
        for ext in meta.get("external", []):
            got = exts.get(ext.get("path"))
            if got is None:
                continue
            ew = "%s external %s" % (where, ext["path"])
            for key in ("size", "sha256", "archive"):
                if got.get(key) != ext.get(key):
                    rep.error("%s: %s is not cart.json's" % (ew, key))
            if got.get("licence", {}).get("name") != ext.get("licence", {}).get("name"):
                rep.error("%s: the licence name is not cart.json's" % ew)
            same_file(got.get("licence"), cid, ext.get("licence", {}).get("file"),
                      ew + " licence", rep)


# -- 3. the release assets --------------------------------------------------------------


def fetch(url, limit):
    req = urllib.request.Request(url, headers={"User-Agent": "moybyte-gpl-carts-validate"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read(limit + 1)
    return data


def download(url, size, where, rep, strict):
    """The asset at `url`, or None (reported) when it cannot be checked."""
    try:
        data = fetch(url, size)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            msg = ("%s: %s answers 404 -- the release is not published (a draft is "
                   "visible only to those with write access), so it is not checked"
                   % (where, url))
            (rep.error if strict else rep.warn)(msg)
            rep.assets_pending += 1
        else:
            rep.error("%s: %s: HTTP %d" % (where, url, exc.code))
        return None
    except (urllib.error.URLError, OSError) as exc:
        rep.error("%s: %s: %s" % (where, url, exc))
        return None
    return data


def check_zip(cart, asset, data, where, rep):
    files = asset.get("files", {})
    folder = cart.get("folder")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = set(z.namelist())
        want = {"%s/%s" % (folder, fn) for fn in files}
        if names != want:
            rep.error("%s: the zip holds %s; the index lists %s"
                      % (where, sorted(names), sorted(want)))
            return False
        for fn, meta in files.items():
            body = z.read("%s/%s" % (folder, fn))
            if len(body) != meta.get("size") or sha256(body) != meta.get("sha256"):
                rep.error("%s: %s in the zip is not the index's" % (where, fn))
                return False
            if fn == "cover.png" and cover_problem(body):
                rep.error("%s: its cover.png is outside SPEC.md 3.6's profile: %s"
                          % (where, cover_problem(body)))
                return False
    return True


def git_bytes(commit, path):
    r = subprocess.run(["git", "-C", ROOT, "show", "%s:%s" % (commit, path)],
                       capture_output=True)
    return r.stdout if r.returncode == 0 else None


def check_source_bundle(cart, data, where, rep):
    """The bundle holds this repository's source at the build commit, and no WAD
    or key."""
    commit = cart.get("build", {}).get("commit", "")
    top = cart.get("source_asset", {}).get("name", "")[:-len(".tar.gz")]
    if subprocess.run(["git", "-C", ROOT, "cat-file", "-e", commit + "^{commit}"],
                      capture_output=True).returncode != 0:
        rep.error("%s: the build commit %s is not in this repository's history"
                  % (where, commit))
        return False
    try:
        tar = tarfile.open(fileobj=io.BytesIO(gzip.decompress(data)), mode="r:")
    except (OSError, EOFError, tarfile.TarError) as exc:
        rep.error("%s: not a tar.gz: %s" % (where, exc))
        return False
    ok = True
    files = {}
    with tar:
        for m in tar.getmembers():
            rel = m.name[len(top) + 1:] if m.name.startswith(top + "/") else None
            if m.name != top and (rel is None or rel.startswith("/") or ".." in rel.split("/")):
                rep.error("%s: %s is outside %s/" % (where, m.name, top))
                ok = False
            elif m.isfile():
                files[rel] = tar.extractfile(m).read()
            elif not m.isdir():
                rep.error("%s: %s is neither a file nor a directory" % (where, m.name))
                ok = False
    listed = subprocess.run(["git", "-C", ROOT, "ls-tree", "-r", "--name-only", commit, "--",
                             "carts/%s" % cart.get("id"), "scripts/build.py",
                             "scripts/jet_recipe.py", "LICENSE"],
                            capture_output=True, text=True).stdout.split()
    for path in listed + ["README.txt"]:
        if path not in files:
            rep.error("%s: %s is missing" % (where, path))
            ok = False
        elif path != "README.txt" and files[path] != git_bytes(commit, path):
            rep.error("%s: %s is not the build commit's" % (where, path))
            ok = False
    for path, body in files.items():
        if FORBIDDEN_NAME.search(path) or body[:4] in WAD_MAGIC or PRIVATE_KEY.search(body):
            rep.error("%s: %s must never be in a release" % (where, path))
            ok = False
    moybyte = {p[len("moybyte/"):]: b for p, b in files.items() if p.startswith("moybyte/")}
    pin = cart.get("build", {}).get("pins", {}).get("moybyte", {}).get("tree_sha256")
    lines = sorted("%s %s" % (p, sha256(b)) for p, b in moybyte.items())
    if not moybyte or sha256("\n".join(lines).encode()) != pin:
        rep.error("%s: moybyte/ is not the build path the build pinned (tree sha256 %s)"
                  % (where, pin))
        ok = False
    if "device/moy_ota.py" in moybyte:
        rep.error("%s: moybyte/device/moy_ota.py (FSL) is never in a source bundle" % where)
        ok = False
    if ok:
        print("%s: the source bundle holds carts/%s/, scripts/ and LICENSE at %s, "
              "moybyte's pinned build path (%d files), and %d more files"
              % (cart.get("id"), cart.get("id"), commit[:12], len(moybyte),
                 len(files) - len(listed) - len(moybyte)))
    return ok


def check_assets(index, rep, strict):
    for cart in index.get("carts", []):
        for asset in cart.get("assets", []) + [cart.get("source_asset") or {}]:
            url, size = asset.get("url"), asset.get("size")
            where = "%s asset %s" % (cart.get("id"), asset.get("name"))
            if not isinstance(url, str) or not is_int(size):
                continue
            data = download(url, size, where, rep, strict)
            if data is None:
                continue
            if len(data) != size or sha256(data) != asset.get("sha256"):
                rep.error("%s: the release's asset is %d bytes, sha256 %s; the index says "
                          "%d bytes, sha256 %s" % (where, len(data), sha256(data), size,
                                                    asset.get("sha256")))
                continue
            if asset is cart.get("source_asset"):
                good = check_source_bundle(cart, data, where, rep)
            else:
                good = check_zip(cart, asset, data, where, rep)
            if good:
                rep.assets_checked += 1
                print("%s: the release's %s matches the index (%d bytes)"
                      % (cart.get("id"), asset.get("name"), size))


# -- 5. the history -------------------------------------------------------------------------


def check_history(rep):
    try:
        listing = subprocess.run(["git", "-C", ROOT, "rev-list", "--objects", "--all"],
                                 capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        rep.error("cannot read the history: %s" % exc)
        return
    objects = {}
    for line in listing.splitlines():
        sha, _, path = line.partition(" ")
        objects.setdefault(sha, set()).add(path)
        if path and FORBIDDEN_NAME.search(path):
            rep.error("the history holds %s (%s): no WAD or key is ever committed"
                      % (path, sha[:12]))
    proc = subprocess.run(["git", "-C", ROOT, "cat-file", "--batch"],
                          input="".join(s + "\n" for s in objects).encode(),
                          capture_output=True, check=True)
    out, i, blobs = proc.stdout, 0, 0
    while i < len(out):
        nl = out.index(b"\n", i)
        head = out[i:nl].split()
        sha, kind, size = head[0].decode(), head[1], int(head[2])
        body = out[nl + 1:nl + 1 + size]
        i = nl + 1 + size + 1
        if kind != b"blob":
            continue
        blobs += 1
        paths = ", ".join(sorted(p for p in objects.get(sha, ()) if p)) or sha[:12]
        if body[:4] in WAD_MAGIC:
            rep.error("the history holds a WAD: %s (%s)" % (paths, sha[:12]))
        if PRIVATE_KEY.search(body) or b"-----BEGIN OPENSSH PRIVATE" + b" KEY-----" in body:
            rep.error("the history holds a private key: %s (%s)" % (paths, sha[:12]))
    print("history: %d blobs on every ref checked for WADs and private keys" % blobs)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--offline", action="store_true", help="skip the release assets")
    ap.add_argument("--strict", action="store_true",
                    help="an unpublished release is an error, not a warning")
    args = ap.parse_args(argv)
    rep = Report()
    index = load(INDEX, rep)
    if isinstance(index, dict):
        check_schema(index, rep)
        check_carts(index, rep)
        if not args.offline:
            check_assets(index, rep, args.strict)
    check_history(rep)
    for w in rep.warnings:
        print("warning: %s" % w)
        if os.environ.get("GITHUB_ACTIONS"):
            print("::warning::%s" % w)
    for e in rep.errors:
        print("error: %s" % e, file=sys.stderr)
        if os.environ.get("GITHUB_ACTIONS"):
            print("::error::%s" % e)
    if rep.errors:
        print("%d error(s)" % len(rep.errors), file=sys.stderr)
        return 1
    assets = ("release assets not checked (--offline)" if args.offline else
              "%d release asset(s) match, %d not published yet"
              % (rep.assets_checked, rep.assets_pending))
    print("ok: index.json and %d cart(s); %s; the history is clean"
          % (len(index.get("carts", [])), assets))
    return 0


if __name__ == "__main__":
    sys.exit(main())
