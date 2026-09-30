#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Nikola Jovicic
"""Build a cart from its recipe, reproducibly.

    python3 scripts/build.py teapot             # -> build/dist/teapot/
    python3 scripts/build.py teapot --twice     # ...then again from scratch; every byte must match
    python3 scripts/build.py teapot --moybyte ~/src/moybyte
    python3 scripts/build.py teapot --unsigned -o ~/teapot-build   # no key needed
    python3 scripts/build.py teapot --verify-release teapot.moy.zip teapot-v1-source.tar.gz

This is gpl-carts' build (moybyte-org/gpl-carts, scripts/build.py): the two
repositories build and publish their carts the same way, and differ in the
module build path they pin and in the source bundle's words about licences.

A cart is carts/<id>/: cart.json (what the index says about it),
manifest.json and config.json (copied into the cart byte for byte), its own
source and data, recipe.py (stages the source with what it builds against and
links main.wasm), and its licences. This script runs the recipe, compiles and signs one module
per chip with Moybyte's tools/wasm_module.py at MOYBYTE_COMMIT, writes
SOURCE.txt (every pin the build used), and packs the folder:

    build/out/<id>/<folder>/          the cart folder, without its external files
    build/dist/<id>/<folder>.zip      the release asset: the cart
    build/dist/<id>/<tag>-source.tar.gz   the release asset: its complete source
    build/dist/<id>/SHA256SUMS        both assets' sha256
    build/dist/<id>/build.json        what scripts/make_index.py reads

Every download and every product stays under build/ (gitignored). No .wasm,
.aot, zip or key is ever committed.

THE MOYBYTE TOOLS are read at a pinned commit, never from a working tree:
from a local moybyte checkout's object store (`git show <commit>:<path>`,
read-only; --moybyte, default ../moybyte) or, when that checkout does not
have the commit, from GitHub at that commit. MOYBYTE_FILES is the module
build path -- the Jet carts' build (tools/jet_cart.py: the flags, and Jet
compiled twice into the teapot), the console's import table it checks a
module against, compile, key, sign -- with Jet and ESP 88's film code as
Moybyte vendors them from CubeCoders at the commits its ports/jet/
jet_vendor.json names; all MIT but two generated pin files, and checked
against MOYBYTE_TREE_SHA256 before anything imports it; it goes into the
source bundle. MOYBYTE_CHECK, device/moy_ota.py (FSL-1.1-MIT), is pinned
by its own sha256, kept apart, and only checks the signatures after the
build; it is never bundled and nothing on the build path imports it. The
compilers are the ones the tools pin by sha256 (the fork's wamrc release).

SIGNING. The modules are signed with the Moybyte OTA signing key, which
tools/wasm_module.py finds itself ($MOYBYTE_OTA_SIGNING_KEY, else
~/.moybyte-ota-signing-key.pem); this script never reads, prints or copies
it, and each module is checked against the public keys the firmware at
MOYBYTE_COMMIT trusts. RSA PKCS#1 v1.5 signatures are deterministic, so a
rebuild signed with the same key is byte-identical. Without the key,
--unsigned builds the same cart with no signature on its modules: a console
runs it while its owner has Settings -> Unknown sources on, and
`install.py --build <out>` installs it. A module signed with any other key is
refused whatever that setting says, so a build of your own stays unsigned.
--verify-release builds the modules unsigned too and holds the released assets
to them: every file identical, each module this build's module plus a
signature the firmware trusts, and the source bundle's tar identical.

THE SOURCE BUNDLE is the cart's whole source as one file in the release, so
a rebuild does not depend on any other repository staying up: carts/<id>/ as
committed; scripts/build.py; LICENSE; MOYBYTE_FILES under moybyte/ (Jet and
the film code among them); and a README that says whose each part is and
gives the commands that make main.wasm and each per-chip module, up to its
signature, from the bundle alone.

REPRODUCIBLE: the engine's __FILE__ strings are mapped to bare file names,
the zip's entries are sorted and STORED with a fixed time and mode, the
bundle's tar entries are sorted with a fixed time, owner and mode and its
gzip header carries no name or time, and no pin floats, so the output
depends on the inputs and not on where, when or by whom it was built. (The
bundle's gzip bytes also depend on the zlib that compressed them; the tar
inside does not, and --verify-release compares that.)
"""

import argparse
import gzip
import hashlib
import importlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CARTS = os.path.join(ROOT, "carts")
BUILD = os.path.join(ROOT, "build")
CACHE = os.path.join(BUILD, "cache")
TOOLCHAIN = os.path.join(BUILD, "toolchain")

REPO = "moybyte-org/mit-carts"
REPO_URL = "https://github.com/" + REPO

# Moybyte's module build path -- the Jet carts' build, compile, key and sign
# -- at the commit this build takes it from, with Jet and ESP 88's film code as
# Moybyte vendors them from CubeCoders (its ports/jet/jet_vendor.json names the
# upstream commits: Jet 19018b52, JetExamples 57b05a24). The tree hash is every
# file's path and sha256, sorted, one per line. Every file here goes into the
# source bundle under moybyte/: the tools are MIT (tools/wat.py and
# native/moycore/libmoy/moy_wasm.c are moy-spec's, vendored into moybyte),
# Jet and the film code are CubeCoders' MIT, and the two pin files are
# generated data naming the runtime fork.
MOYBYTE_REPO = "moybyte-org/moybyte"
MOYBYTE_COMMIT = "925af7d360bc258b48f2eb0811f9787657c6d383"
MOYBYTE_TOOLS = (
    "LICENSES/MIT.md",                      # the MIT text the tools' headers name
    "native/moy_wasm/moy_wasm_key.h",       # each chip's compiler flags and the signature layout
    "native/moy_wasm/wamr_pin.h",           # data: the runtime fork a board built here wants
    "native/moy_wasm/wamr_vendor.json",     # data: the same fork commit, as the tools read it
    "native/moycore/libmoy/moy_wasm.c",     # the console's import table jet_cart.py checks against
    "tools/jet_cart.py",                    # the Jet carts' build: flags, units, the teapot's two Jets
    "tools/ota_sign.py",                    # the signature scheme, imported by wasm_module.py
    "tools/wasm_cart.py",                   # aot_name: where a board looks for its module
    "tools/wasm_module.py",                 # compile, key and sign a module per chip
    "tools/wat.py",                         # imported by wasm_cart.py
)
MOYBYTE_JET = (
    "ports/jet/examples/LICENSE",
    "ports/jet/examples/esp32-neon-film/main/City.hpp",
    "ports/jet/examples/esp32-neon-film/main/Film.hpp",
    "ports/jet/examples/esp32-neon-film/main/RoadTrack.hpp",
    "ports/jet/examples/esp32-neon-film/main/Vehicle.hpp",
    "ports/jet/examples/esp32-neon-film/main/World.hpp",
    "ports/jet/examples/esp32-neon-film/main/firmware/JetConfig.hpp",
    "ports/jet/jet/LICENSE",
    "ports/jet/jet/src/BlendSpans.cpp",
    "ports/jet/jet/src/BlendSpans.hpp",
    "ports/jet/jet/src/Camera.cpp",
    "ports/jet/jet/src/Camera.hpp",
    "ports/jet/jet/src/DepthBuckets.hpp",
    "ports/jet/jet/src/EnvironmentMapping.hpp",
    "ports/jet/jet/src/FastMath.hpp",
    "ports/jet/jet/src/Light.cpp",
    "ports/jet/jet/src/Light.hpp",
    "ports/jet/jet/src/Material.cpp",
    "ports/jet/jet/src/Material.hpp",
    "ports/jet/jet/src/Math.hpp",
    "ports/jet/jet/src/ObjLoader.h",
    "ports/jet/jet/src/Object.cpp",
    "ports/jet/jet/src/Object.hpp",
    "ports/jet/jet/src/ParticleSystem.hpp",
    "ports/jet/jet/src/Picking.hpp",
    "ports/jet/jet/src/PostFX.cpp",
    "ports/jet/jet/src/PostFX.hpp",
    "ports/jet/jet/src/Primitives.cpp",
    "ports/jet/jet/src/Primitives.hpp",
    "ports/jet/jet/src/Renderer.cpp",
    "ports/jet/jet/src/Renderer.hpp",
    "ports/jet/jet/src/Scene.cpp",
    "ports/jet/jet/src/Scene.hpp",
    "ports/jet/jet/src/Shader.hpp",
    "ports/jet/jet/src/Specular.hpp",
    "ports/jet/jet/src/Sprite2D.cpp",
    "ports/jet/jet/src/Sprite2D.hpp",
    "ports/jet/jet/src/Texture.cpp",
    "ports/jet/jet/src/Texture.hpp",
    "ports/jet/jet/src/TextureSpans.hpp",
    "ports/jet/jet/src/TriangleSpans.hpp",
    "ports/jet/jet/src/TrigLUT.cpp",
    "ports/jet/jet/src/TrigLUT.hpp",
)
MOYBYTE_FILES = MOYBYTE_TOOLS + MOYBYTE_JET
MOYBYTE_TREE_SHA256 = "db7e0713f2fc751c18d355a567953d5c9d446c92a73d3686f0c07ef85bbdc521"
MOYBYTE_MIT = ("tools/jet_cart.py", "tools/ota_sign.py", "tools/wasm_cart.py",
               "tools/wasm_module.py", "tools/wat.py", "native/moy_wasm/moy_wasm_key.h",
               "native/moycore/libmoy/moy_wasm.c")
MOYBYTE_DATA = ("native/moy_wasm/wamr_pin.h", "native/moy_wasm/wamr_vendor.json")

# The signature check after the build, and nothing else: the public keys a
# board trusts, and the arithmetic that checks a signature against them. It is
# FSL-1.1-MIT, so it is never in the source bundle, and nothing on the build
# path imports it.
MOYBYTE_CHECK = ("device/moy_ota.py",
                 "b2a36287f8051e0d9cd520fa2d0fd92254a2e5dfcb9cf159a8ba1be57608a670")

# wasi-sdk 24: clang 18 and wasi-libc.
WASI_SDK_VERSION = "24.0"
WASI_SDK_URL = ("https://github.com/WebAssembly/wasi-sdk/releases/download/"
                "wasi-sdk-24/wasi-sdk-24.0-x86_64-linux.tar.gz")
WASI_SDK_SHA256 = "c6c38aab56e5de88adf6c1ebc9c3ae8da72f88ec2b656fb024eda8d4167a0bc5"

ZIP_TIME = (1980, 1, 1, 0, 0, 0)
SOURCE_TIME = 315532800                  # the same instant, for the source bundle's tar


class BuildError(RuntimeError):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def tree_sha256(files):
    """The sha256 of a set of files: every "path sha256", sorted, one per line."""
    return sha256("\n".join(sorted("%s %s" % (p, sha256(d)) for p, d in files.items())).encode())


def _download(url):
    req = urllib.request.Request(url, headers={"User-Agent": "moybyte-mit-carts-build"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def fetch(url, pin, name):
    """The bytes at `url`, cached as build/cache/`name`. With a `pin` they are
    refused unless they hash to it; without one the caller checks them (a
    GitHub source tarball, whose bytes GitHub does not promise)."""
    path = os.path.join(CACHE, name)
    if not os.path.isfile(path):
        os.makedirs(CACHE, exist_ok=True)
        print("fetching %s" % url)
        data = _download(url)
        if pin and sha256(data) != pin:
            raise BuildError("%s hashes to %s; the pin is %s" % (url, sha256(data), pin))
        with open(path + ".part", "wb") as f:
            f.write(data)
        os.replace(path + ".part", path)
    with open(path, "rb") as f:
        data = f.read()
    if pin and sha256(data) != pin:
        raise BuildError("%s hashes to %s; the pin is %s (delete it to refetch)"
                         % (path, sha256(data), pin))
    return data


def git(*args):
    return subprocess.run(["git", "-C", ROOT] + list(args), capture_output=True,
                          text=True, check=True).stdout.strip()


def source_commit(allow_dirty):
    """This repository's commit, which SOURCE.txt names. A tree with changes is
    refused: the cart would name a commit it was not built from."""
    commit = git("rev-parse", "HEAD")
    if git("status", "--porcelain"):
        if not allow_dirty:
            raise BuildError("the working tree has changes; commit them (the cart names "
                             "the commit it was built from) or pass --allow-dirty")
        return commit + "+dirty"
    return commit


# -- Moybyte's tools --------------------------------------------------------------


def _moybyte_file(checkout, path):
    if checkout:
        r = subprocess.run(["git", "-C", checkout, "show", "%s:%s" % (MOYBYTE_COMMIT, path)],
                           capture_output=True)
        if r.returncode == 0:
            return r.stdout
    return _download("https://raw.githubusercontent.com/%s/%s/%s"
                     % (MOYBYTE_REPO, MOYBYTE_COMMIT, path))


def moybyte_tools(checkout):
    """(wasm_module, wasm_cart, root): the build path imported from
    MOYBYTE_FILES at MOYBYTE_COMMIT, written under build/moybyte/<commit>
    after their tree hash checks, with the signature check pointed at
    MOYBYTE_CHECK's file, which is kept apart under build/moybyte-check/."""
    root = os.path.join(BUILD, "moybyte", MOYBYTE_COMMIT[:12])
    have = {}
    for path in MOYBYTE_FILES:
        p = os.path.join(root, path)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                have[path] = f.read()
    if len(have) != len(MOYBYTE_FILES) or tree_sha256(have) != MOYBYTE_TREE_SHA256:
        have = {path: _moybyte_file(checkout, path) for path in MOYBYTE_FILES}
        got = tree_sha256(have)
        if got != MOYBYTE_TREE_SHA256:
            raise BuildError("moybyte %s: the build path hashes to %s; the pin is %s"
                             % (MOYBYTE_COMMIT[:12], got, MOYBYTE_TREE_SHA256))
        if os.path.isdir(root):
            shutil.rmtree(root)
        for path, data in have.items():
            p = os.path.join(root, path)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data)
    check = os.path.join(BUILD, "moybyte-check", MOYBYTE_COMMIT[:12], *MOYBYTE_CHECK[0].split("/"))
    data = None
    if os.path.isfile(check):
        with open(check, "rb") as f:
            data = f.read()
    if data is None or sha256(data) != MOYBYTE_CHECK[1]:
        data = _moybyte_file(checkout, MOYBYTE_CHECK[0])
        if sha256(data) != MOYBYTE_CHECK[1]:
            raise BuildError("moybyte %s: %s hashes to %s; the pin is %s" % (
                MOYBYTE_COMMIT[:12], MOYBYTE_CHECK[0], sha256(data), MOYBYTE_CHECK[1]))
        os.makedirs(os.path.dirname(check), exist_ok=True)
        with open(check, "wb") as f:
            f.write(data)
    for var in ("MOYBYTE_WAMRC_XTENSA", "MOYBYTE_WAMRC_RISCV32"):
        if os.environ.get(var):
            raise BuildError("$%s is set: a release is built with the pinned compilers only"
                             % var)
    if root not in sys.path:
        sys.path.insert(0, root)
    wasm_module = importlib.import_module("tools.wasm_module")
    wasm_cart = importlib.import_module("tools.wasm_cart")
    if os.path.dirname(os.path.abspath(wasm_module.__file__)) != os.path.join(root, "tools"):
        raise BuildError("tools.wasm_module was imported from %s, not the pinned copy"
                         % wasm_module.__file__)
    # The pinned compilers are cached once per compiler release, which the
    # tool names; it still refuses one whose sha256 is not its pin. verify()
    # reads the check file.
    wasm_module.DIST = os.path.join(TOOLCHAIN, "wamrc", os.path.basename(wasm_module.RELEASE))
    wasm_module.MOY_OTA = check
    if any(os.path.basename(getattr(m, "__file__", None) or "") == "moy_ota.py"
           for m in list(sys.modules.values())):
        raise BuildError("the build path imported moy_ota.py")
    pin_h = have["native/moy_wasm/wamr_pin.h"].decode()
    if '"%s"' % wasm_module.fork_commit() not in pin_h:
        raise BuildError("moybyte %s: wamr_pin.h and wamr_vendor.json name different forks"
                         % MOYBYTE_COMMIT[:12])
    return wasm_module, wasm_cart, root


def wasi_sdk():
    """The pinned wasi-sdk, fetched and unpacked under build/toolchain."""
    home = os.path.join(TOOLCHAIN, "wasi-sdk-" + WASI_SDK_VERSION)
    if os.path.isfile(os.path.join(home, "bin", "clang")):
        return home
    data = fetch(WASI_SDK_URL, WASI_SDK_SHA256, os.path.basename(WASI_SDK_URL))
    tmp = home + ".part"
    if os.path.isdir(tmp):
        shutil.rmtree(tmp)
    os.makedirs(tmp)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        top = tar.getmembers()[0].name.split("/")[0]
        kwargs = {"filter": "tar"} if hasattr(tarfile, "tar_filter") else {}
        tar.extractall(tmp, **kwargs)
    os.replace(os.path.join(tmp, top), home)
    shutil.rmtree(tmp)
    return home


# -- the build -----------------------------------------------------------------------


class Context:
    """What a recipe is handed: where to stage, the toolchain, the fetcher,
    and the pinned moybyte tree the module build path came from."""

    def __init__(self, cart_id, cart_dir, stage, sdk, wasm_module, file_prefix,
                 moybyte_root):
        self.cart_id = cart_id
        self.cart_dir = cart_dir
        self.stage = stage
        self.wasi_sdk = sdk
        self.wasm_module = wasm_module
        self.file_prefix = file_prefix
        self.moybyte = moybyte_root
        self.error = BuildError

    def fetch(self, url, pin, name):
        return fetch(url, pin, name)

    def read(self, name):
        with open(os.path.join(self.cart_dir, name), "rb") as f:
            return f.read()


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_recipe(cart_id):
    path = os.path.join(CARTS, cart_id, "recipe.py")
    spec = importlib.util.spec_from_file_location("recipe_" + cart_id, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def asset_url(meta, name):
    return "%s/releases/download/%s/%s" % (REPO_URL, meta["release"], name)


def source_text(meta, commit, pins, bundle):
    lines = [
        "%s for Moybyte consoles: where every byte of this cart comes from." % meta["name"],
        "",
        "Its whole source is one file in the same release:",
        "",
        "  %s" % asset_url(meta, bundle["name"]),
        "  %d bytes, sha256 %s" % (bundle["size"], bundle["sha256"]),
        "",
        "This cart was built by scripts/build.py from:",
        "",
        "  mit-carts     %s/tree/%s/carts/%s" % (REPO_URL, commit, meta["id"]),
        "                commit %s" % commit,
    ]
    for key in sorted(pins):
        pin = pins[key]
        lines.append("  %-13s %s" % (key, pin["url"]))
        for field in ("commit", "tree_sha256", "sha256", "version", "note"):
            if field in pin:
                lines.append("                %s %s" % (field.replace("_", " "), pin[field]))
    lines += [
        "",
        "To rebuild it, byte for byte:",
        "",
        "  git clone %s && cd mit-carts" % REPO_URL,
        "  git checkout %s" % commit,
        "  python3 scripts/build.py %s" % meta["id"],
        "",
        "The per-chip modules are signed with the Moybyte OTA key, which only",
        "Moybyte has. Without it, --unsigned builds the cart with unsigned modules,",
        "which a console runs with Settings -> Unknown sources on, and this checks",
        "a release against the source -- every file identical, each module this",
        "build's plus a signature the firmware trusts, the source bundle's tar",
        "identical:",
        "",
        "  python3 scripts/build.py %s --verify-release %s.zip %s"
        % (meta["id"], meta["folder"], bundle["name"]),
        "",
    ]
    return "\n".join(lines)


def pack(folder, name, out):
    """`folder`'s files as `name`/<file> in a STORED zip at `out`, sorted, with
    a fixed time and mode."""
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        for fn in sorted(os.listdir(folder)):
            with open(os.path.join(folder, fn), "rb") as f:
                data = f.read()
            info = zipfile.ZipInfo("%s/%s" % (name, fn), ZIP_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            z.writestr(info, data)


def forbidden(path, data):
    """Why `path` must never ship in a source bundle, or None."""
    if path.lower().endswith((".wad", ".pem", ".key", ".p12", ".pfx")):
        return "its name"
    if data[:4] in (b"IWAD", b"PWAD"):
        return "a WAD's magic"
    if b"PRIVATE" + b" KEY-----" in data:
        return "a private key block"
    return None


def _wrap(argv, first="  ", cont="      ", width=78):
    """A command line as shell text, wrapped with backslashes."""
    out, line = [], first
    for arg in argv:
        if len(line) + len(arg) > width and line.strip():
            out.append(line.rstrip() + " \\")
            line = cont
        line += arg + " "
    out.append(line.rstrip())
    return out


def bundle_readme(meta, commit, made, main_sha256, modules, compiler_release):
    top = "%s-source" % meta["release"]
    cid = meta["id"]
    folder = meta["folder"]
    lines = [
        "%s for Moybyte consoles, release %s: its whole source."
        % (meta["name"], meta["release"]),
        "",
        "This is the source of %s.zip, the cart in the same release, built by" % folder,
        "%s at commit" % REPO_URL,
        "%s." % commit,
        "",
        "  %s/" % top,
        "    %-17s the cart as the repository has it: its own source, data," % ("carts/%s/" % cid),
        "    %-17s manifest, recipe and licences" % "",
        "    %-17s the build that produced the cart, and the recipe the" % "scripts/",
        "    %-17s cart's recipe.py runs" % "",
        "    %-17s Moybyte's module build path, at moybyte commit" % "moybyte/",
        "    %-17s %s:" % ("", MOYBYTE_COMMIT),
        "    %-17s the Jet carts' build, the tools that compile, key and sign a" % "",
        "    %-17s module per chip, Jet and the film's code as Moybyte vendors" % "",
        "    %-17s them, the pin files and the MIT text" % "",
        "    %-17s the MIT licence" % "LICENSE",
        "",
        "Licences:",
        "",
    ]
    for name, paths, notes in (
            ("MIT (this repository)",
             ["carts/%s/" % cid, "scripts/build.py", "scripts/jet_recipe.py", "README.txt"],
             ["The text is LICENSE. carts/%s/LICENSES.txt says whose each part of" % cid,
              "the cart is: the port is this repository's, Jet and the example it",
              "ports are CubeCoders Limited's, under the same licence."]),
            ("MIT (Moybyte)", ["moybyte/" + p for p in MOYBYTE_MIT],
             ["The text is moybyte/LICENSES/MIT.md. moybyte/tools/wat.py and",
              "moybyte/native/moycore/libmoy/moy_wasm.c are moy-spec's, vendored into",
              "moybyte, and MIT there too."]),
            ("MIT (CubeCoders Limited)", ["moybyte/ports/jet/jet/", "moybyte/ports/jet/examples/"],
             ["Jet and JetExamples' code; each folder carries its LICENSE."]),
            ("data", ["moybyte/" + p for p in MOYBYTE_DATA],
             ["Generated records of the runtime fork commit the modules are",
              "keyed for."])):
        lines.append("  %s" % name)
        lines += ["    " + p for p in paths]
        lines += ["    " + n for n in notes]
        lines.append("")
    lines += [
        "Moybyte's %s (FSL-1.1-MIT) is not here: it only checks, after the" % MOYBYTE_CHECK[0],
        "build, that a signature is one a board trusts, and nothing below needs it.",
        "",
        "main.wasm from this bundle alone, with wasi-sdk %s" % WASI_SDK_VERSION,
        "(%s," % WASI_SDK_URL,
        "sha256 %s) and Python 3.8+:" % WASI_SDK_SHA256,
        "",
        "  cd %s" % top,
        "  cp -r carts/%s moybyte/ports/jet/%s" % (cid, folder),
        "  WASI_SDK_PATH=/path/to/wasi-sdk-%s python3 moybyte/tools/jet_cart.py out --cart %s"
        % (WASI_SDK_VERSION, cid),
        "",
        "That writes out/%s/main.wasm, the file the cart carries: sha256" % folder,
        "%s." % main_sha256,
        "",
    ]
    if modules:
        lines += [
            "The per-chip modules from it, up to their signatures. The tool fetches",
            "its pinned compilers (Linux x86-64), checked by sha256, from the WAMR",
            "fork's release",
            compiler_release.replace("/releases/download/", "/releases/tag/"),
            "into moybyte/experiments/wasm_aot/toolchain/dist/:",
            "",
        ]
        for chip in sorted(modules):
            lines += _wrap(["python3", "moybyte/tools/wasm_module.py", "build",
                            "out/%s/main.wasm" % folder, "--chip", chip, "--unsigned",
                            "-o", modules[chip]["name"]])
        lines += [
            "",
            "Each writes the module the cart carries, without its signature. The cart's",
            "file is this module followed by an RSA signature over it, the signature's",
            "length (4 bytes, little-endian) and \"moybyte-sig1\"; moy_wasm_key.h lays",
            "it out. Signing needs Moybyte's update-signing key, which only Moybyte has:",
            "a module signed with any other key is refused by a board. A build from this",
            "bundle is unsigned, and runs on a console with Settings -> Unknown sources on.",
            "",
        ]
        for chip in sorted(modules):
            m = modules[chip]
            lines.append("  %-18s %d bytes, sha256" % (m["name"], m["unsigned_size"]))
            lines.append("    %s" % m["unsigned_sha256"])
        lines.append("")
    lines += [
        "The whole cart, from a checkout of this repository (SOURCE.txt in the cart",
        "names every pin):",
        "",
        "  git clone %s && cd mit-carts" % REPO_URL,
        "  git checkout %s" % commit,
        "  python3 scripts/build.py %s --unsigned" % cid,
        "",
    ]
    return "\n".join(lines)


def pack_source(files, top, out):
    """`files` ({path: bytes}) under `top`/ in a tar.gz at `out`: entries sorted,
    directories included, a fixed time, root owner and modes, and a gzip
    header with no name and no time. Returns the tar's bytes."""
    paths = set(files)
    for path in files:
        parts = path.split("/")[:-1]
        paths.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        tar.addfile(_tarinfo(top, None))
        for path in sorted(paths):
            data = files.get(path)
            tar.addfile(_tarinfo("%s/%s" % (top, path), data),
                        io.BytesIO(data) if data is not None else None)
    blob = raw.getvalue()
    with open(out, "wb") as f:
        with gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0, compresslevel=9) as gz:
            gz.write(blob)
    return blob


def _tarinfo(name, data):
    info = tarfile.TarInfo(name)
    info.mtime = SOURCE_TIME
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    if data is None:
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
    else:
        info.mode = 0o644
        info.size = len(data)
    return info


def source_bundle(meta, commit, made, main_sha256, modules, moybyte_root, compiler_release,
                  dist):
    """Write the release's source bundle into `dist`. Returns its asset entry."""
    files = dict(made.get("sources", {}))
    for path in MOYBYTE_FILES:
        with open(os.path.join(moybyte_root, *path.split("/")), "rb") as f:
            files["moybyte/" + path] = f.read()
    tracked = git("ls-files", "-z", "--", "carts/%s" % meta["id"], "scripts/build.py",
                  "scripts/jet_recipe.py",
                  "LICENSE").split("\0")
    for path in tracked:
        if path:
            with open(os.path.join(ROOT, *path.split("/")), "rb") as f:
                files[path] = f.read()
    files["README.txt"] = bundle_readme(meta, commit, made, main_sha256, modules,
                                        compiler_release).encode()
    for path, data in files.items():
        why = forbidden(path, data)
        if why:
            raise BuildError("%s must never ship in a source bundle (%s)" % (path, why))
    name = "%s-source.tar.gz" % meta["release"]
    tar = pack_source(files, "%s-source" % meta["release"], os.path.join(dist, name))
    with open(os.path.join(dist, name), "rb") as f:
        blob = f.read()
    return {"name": name, "size": len(blob), "sha256": sha256(blob),
            "tar_sha256": sha256(tar), "files": len(files)}


def build(cart_id, out_root, checkout, commit, file_prefix="", signed=True):
    """Build carts/`cart_id` into `out_root`/out and `out_root`/dist. Returns
    build.json's content. `signed=False` leaves the modules' signatures off:
    a cart a console runs with Unknown sources on, and what --verify-release
    compares."""
    cart_dir = os.path.join(CARTS, cart_id)
    meta = load_json(os.path.join(cart_dir, "cart.json"))
    manifest = load_json(os.path.join(cart_dir, "manifest.json"))
    if meta["id"] != cart_id:
        raise BuildError("carts/%s/cart.json says its id is %r" % (cart_id, meta["id"]))
    wasm_module, wasm_cart, moybyte_root = moybyte_tools(checkout)
    ota_sign = wasm_module.ota_sign
    if signed and not (os.environ.get(ota_sign.ENV_KEY) or os.path.isfile(ota_sign.DEFAULT_KEY)):
        raise BuildError("no signing key ($%s or %s); only Moybyte signs a release. "
                         "--unsigned builds the cart without one, for a console with "
                         "Settings -> Unknown sources on" % (ota_sign.ENV_KEY, ota_sign.DEFAULT_KEY))
    sdk = wasi_sdk()
    recipe = load_recipe(cart_id)

    stage = os.path.join(BUILD, "stage", cart_id)
    if os.path.isdir(stage):
        shutil.rmtree(stage)
    os.makedirs(stage)
    folder = os.path.join(out_root, "out", cart_id, meta["folder"])
    if os.path.isdir(folder):
        shutil.rmtree(folder)
    os.makedirs(folder)

    ctx = Context(cart_id, cart_dir, stage, sdk, wasm_module, file_prefix, moybyte_root)
    made = recipe.build(ctx, folder)
    wasm = made["wasm"]
    main = manifest.get("main", "main.wasm")
    with open(os.path.join(folder, main), "rb") as f:
        if f.read() != wasm:
            raise BuildError("the recipe's %s is not the wasm it returned" % main)

    keys, modules = {}, {}
    for chip in meta["chips"]:
        path = os.path.join(folder, wasm_cart.aot_name(main, chip))
        wasm_module.build(wasm, chip, path, signed=signed)
        with open(path, "rb") as f:
            data = f.read()
        why = wasm_module.verify(data, chip) if signed else None
        if why is not None:
            raise BuildError("%s: a board built at moybyte %s refuses it: %s"
                             % (os.path.basename(path), MOYBYTE_COMMIT[:12], why))
        keys[chip] = wasm_module.key_tail(chip)
        module, _sig = wasm_module.split(data)
        modules[chip] = {"name": os.path.basename(path), "unsigned_size": len(module),
                         "unsigned_sha256": sha256(module)}

    compilers = wasm_module.COMPILERS
    pins = dict(made["pins"])
    pins["moybyte"] = {
        "url": "https://github.com/%s/tree/%s" % (MOYBYTE_REPO, MOYBYTE_COMMIT),
        "commit": MOYBYTE_COMMIT, "tree_sha256": MOYBYTE_TREE_SHA256,
        "note": "the module build path, scripts/build.py's MOYBYTE_FILES (in the source "
                "bundle under moybyte/); device/moy_ota.py only checks the signatures",
    }
    pins["wasi-sdk"] = {"url": WASI_SDK_URL, "sha256": WASI_SDK_SHA256,
                        "version": WASI_SDK_VERSION}
    for target in sorted(compilers):
        pins["wamrc-" + target] = {"url": compilers[target]["url"],
                                   "sha256": compilers[target]["sha256"]}
    pins["wamr-fork"] = {
        "url": "https://github.com/moybyte-org/wasm-micro-runtime/tree/%s"
               % wasm_module.fork_commit(),
        "commit": wasm_module.fork_commit(),
        "note": "the runtime the modules are keyed for; a board built for another refuses them",
    }
    dist = os.path.join(out_root, "dist", cart_id)
    if os.path.isdir(dist):
        shutil.rmtree(dist)
    os.makedirs(dist)
    bundle = source_bundle(meta, commit, made, sha256(wasm), modules, moybyte_root,
                           wasm_module.RELEASE, dist)
    with open(os.path.join(folder, "SOURCE.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(source_text(meta, commit, pins, bundle))

    names = sorted(os.listdir(folder))
    for fn in names:
        if fn.lower().endswith(".wad") or fn in [e["path"] for e in meta.get("external", [])]:
            raise BuildError("%s is an external file and must never be in the cart asset" % fn)
    files = {}
    for fn in names:
        with open(os.path.join(folder, fn), "rb") as f:
            data = f.read()
        files[fn] = {"size": len(data), "sha256": sha256(data)}
    for fn in ("manifest.json", "config.json"):
        if fn in files and files[fn]["sha256"] != sha256(ctx.read(fn)):
            raise BuildError("the cart's %s is not carts/%s/%s byte for byte" % (fn, cart_id, fn))

    asset = meta["folder"] + ".zip"
    pack(folder, meta["folder"], os.path.join(dist, asset))
    with open(os.path.join(dist, asset), "rb") as f:
        blob = f.read()
    with open(os.path.join(dist, "SHA256SUMS"), "w", newline="\n") as f:
        for digest, name in sorted([(sha256(blob), asset),
                                    (bundle["sha256"], bundle["name"])], key=lambda x: x[1]):
            f.write("%s  %s\n" % (digest, name))
    info = {
        "id": cart_id,
        "commit": commit,
        "source": "%s/tree/%s/carts/%s" % (REPO_URL, commit, cart_id),
        "asset": {"name": asset, "size": len(blob), "sha256": sha256(blob)},
        "source_asset": {k: bundle[k] for k in ("name", "size", "sha256", "tar_sha256")},
        "files": files,
        "memory": manifest.get("memory"),
        "keys": keys,
        "modules": modules,
        "pins": pins,
    }
    with open(os.path.join(dist, "build.json"), "w", newline="\n") as f:
        json.dump(info, f, indent=2, sort_keys=True)
        f.write("\n")
    print("%s: %s, %d bytes, sha256 %s" % (cart_id, asset, len(blob), sha256(blob)))
    print("%s: %s, %d bytes, sha256 %s (%d files)" % (cart_id, bundle["name"], bundle["size"],
                                                     bundle["sha256"], bundle["files"]))
    for fn in names:
        print("  %-22s %9d  %s" % (fn, files[fn]["size"], files[fn]["sha256"]))
    return info


def compare(a, b):
    """[relative paths whose bytes differ, or which only one tree has]."""
    def walk(top):
        out = {}
        for d, _dirs, fns in os.walk(top):
            for fn in fns:
                p = os.path.join(d, fn)
                out[os.path.relpath(p, top)] = p
        return out
    wa, wb = walk(a), walk(b)
    diff = sorted(set(wa) ^ set(wb))
    for rel in sorted(set(wa) & set(wb)):
        with open(wa[rel], "rb") as fa, open(wb[rel], "rb") as fb:
            if fa.read() != fb.read():
                diff.append(rel)
    return diff


def verify_release(cart_id, assets, checkout, commit):
    """Build `cart_id` unsigned and hold released assets to it. The cart's zip:
    every file byte for byte, and each module as this build's module plus a
    signature the firmware at MOYBYTE_COMMIT trusts. The source bundle: the
    tar inside it byte for byte (its gzip layer depends on the zlib that
    wrote it). Needs no signing key."""
    info = build(cart_id, os.path.join(BUILD, "verify-release"), checkout, commit,
                 signed=False)
    wasm_module, _wasm_cart, _root = moybyte_tools(checkout)
    meta = load_json(os.path.join(CARTS, cart_id, "cart.json"))
    out = os.path.join(BUILD, "verify-release")
    folder = os.path.join(out, "out", cart_id, meta["folder"])
    for asset in assets:
        name = os.path.basename(asset)
        if name == info["source_asset"]["name"]:
            with open(asset, "rb") as f:
                blob = f.read()
            with open(os.path.join(out, "dist", cart_id, name), "rb") as f:
                ours = f.read()
            if gzip.decompress(blob) != gzip.decompress(ours):
                raise BuildError("%s: its tar is not this source's" % name)
            print("  %-22s %s" % (name, "identical" if blob == ours else
                                  "the same tar; the gzip layer differs (another zlib)"))
            continue
        if name != info["asset"]["name"]:
            raise BuildError("%s is not an asset of %s (%s, %s)" % (
                name, cart_id, info["asset"]["name"], info["source_asset"]["name"]))
        with zipfile.ZipFile(asset) as z:
            released = {n.split("/", 1)[1]: z.read(n) for n in z.namelist()}
        if sorted(released) != sorted(info["files"]):
            raise BuildError("the release holds %s; this build makes %s"
                             % (sorted(released), sorted(info["files"])))
        for fn in sorted(released):
            with open(os.path.join(folder, fn), "rb") as f:
                ours = f.read()
            data = released[fn]
            if fn.endswith(".aot"):
                chip = fn.split(".")[-2]
                module, sig = wasm_module.split(data)
                if module != ours:
                    raise BuildError("%s: the released module is not this build's" % fn)
                why = wasm_module.verify(data, chip)
                if not sig or why is not None:
                    raise BuildError("%s: the module is this build's, but its signature is "
                                     "refused: %s" % (fn, why or "none"))
                print("  %-22s this build's module, plus a trusted %d-byte signature"
                      % (fn, len(sig)))
            elif data != ours:
                raise BuildError("%s: the released file is not this build's" % fn)
            else:
                print("  %-22s identical" % fn)
    print("%s: %s correspond to this source" % (cart_id, ", ".join(
        os.path.basename(a) for a in assets)))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cart", help="the cart's id: a directory under carts/")
    ap.add_argument("--moybyte", default=os.path.join(os.path.dirname(ROOT), "moybyte"),
                    help="a local moybyte checkout to read the pinned tools from "
                    "(read-only; default ../moybyte; GitHub when it lacks the commit)")
    ap.add_argument("--twice", action="store_true",
                    help="build a second time from scratch and require identical bytes")
    ap.add_argument("-o", "--out", default=BUILD, help="where out/ and dist/ go (default build/)")
    ap.add_argument("--allow-dirty", action="store_true",
                    help="build from a tree with changes (the cart says so)")
    ap.add_argument("--unsigned", action="store_true",
                    help="leave the modules unsigned: no key needed, and a console runs "
                    "the cart with Settings -> Unknown sources on")
    ap.add_argument("--verify-release", metavar="ASSET", nargs="+",
                    help="build unsigned and check released assets against this source: "
                    "the cart's zip (its modules signed with a key the firmware trusts) "
                    "and the source bundle")
    ap.add_argument("--file-prefix", default="", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    checkout = args.moybyte if os.path.isdir(os.path.join(args.moybyte, ".git")) else None
    try:
        commit = source_commit(args.allow_dirty)
        if args.verify_release:
            verify_release(args.cart, args.verify_release, checkout, commit)
            return 0
        build(args.cart, args.out, checkout, commit, args.file_prefix, not args.unsigned)
        if args.twice:
            again = os.path.join(BUILD, "again")
            build(args.cart, again, checkout, commit, args.file_prefix, not args.unsigned)
            diff = compare(os.path.join(args.out, "out", args.cart),
                           os.path.join(again, "out", args.cart))
            diff += compare(os.path.join(args.out, "dist", args.cart),
                            os.path.join(again, "dist", args.cart))
            if diff:
                raise BuildError("the second build differs: %s" % ", ".join(diff))
            print("%s: the second build is byte-identical" % args.cart)
        if args.unsigned:
            print("%s: the modules are unsigned; a console runs this cart with Settings -> "
                  "Unknown sources on. To install it:" % args.cart)
            print("  python3 install.py %s /path/to/sdcard/moybyte/carts --build %s"
                  % (args.cart, args.out))
    except (BuildError, subprocess.CalledProcessError) as exc:
        print("build: %s" % exc, file=sys.stderr)
        return 2
    except Exception as exc:  # the moybyte tools raise their own ToolError
        if type(exc).__name__ != "ToolError":
            raise
        print("build: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
