# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Nikola Jovicic
"""The recipe both Jet carts run (each cart's recipe.py hands it its id).

A Jet cart's main.wasm is built by Moybyte's tools/jet_cart.py, at the
moybyte commit scripts/build.py pins: the flags, the units and, for the
teapot, Jet compiled twice into one module all have that one home, and
Moybyte's own tests and on-glass guards build its vendored copy of these
carts with the same tool. This stages a moybyte-shaped tree -- the pinned
build path, Jet and the film's code as moybyte vendors them, and this cart's
folder where jet_cart.py looks for it -- runs the build there, and writes the
release's cart: the folder's own files, flat, and main.wasm. The build maps
the stage's path out of the binary, so the module does not depend on where it
was built.

A cart folder here holds cart.json, recipe.py and README.md for this
repository, and everything else is the cart: its manifest, config, licences
and data go into the release as they are, and its src/ is compiled.
"""

import importlib.util
import os
import shutil

# Where Jet and the film's code come from, as moybyte's ports/jet/jet_vendor.json
# records them at the pinned commit.
JET = {"url": "https://github.com/CubeCoders/Jet/tree/"
              "19018b52c04d92c615d1ade2db5eb7198c7af21c",
       "commit": "19018b52c04d92c615d1ade2db5eb7198c7af21c",
       "note": "as moybyte vendors it at the pinned commit (ports/jet/jet)"}
EXAMPLES = {"url": "https://github.com/CubeCoders/JetExamples/tree/"
                   "57b05a240f5bcaa02a18d62a1206ce7053dc09dc",
            "commit": "57b05a240f5bcaa02a18d62a1206ce7053dc09dc",
            "note": "the example the cart ports, and the film's code as moybyte "
                    "vendors it (ports/jet/examples)"}

# This repository's files in a cart folder, never the cart's.
REPO_FILES = ("cart.json", "recipe.py", "README.md")


def build(ctx, folder):
    root = os.path.join(ctx.stage, "moybyte")
    shutil.copytree(ctx.moybyte, root)
    spec = importlib.util.spec_from_file_location(
        "jet_cart_%s" % ctx.cart_id, os.path.join(root, "tools", "jet_cart.py"))
    jet_cart = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(jet_cart)
    if ctx.cart_id not in jet_cart.CARTS:
        raise ctx.error("moybyte's jet_cart.py builds %s, not %r"
                        % (", ".join(sorted(jet_cart.CARTS)), ctx.cart_id))
    staged = jet_cart.cart_spec(ctx.cart_id).folder
    shutil.copytree(ctx.cart_dir, staged,
                    ignore=shutil.ignore_patterns("__pycache__", *REPO_FILES))
    try:
        wasm = jet_cart.compile_wasm(sdk=ctx.wasi_sdk, cart=ctx.cart_id)
    except jet_cart.BuildError as exc:
        raise ctx.error(str(exc))

    main = jet_cart.manifest(ctx.cart_id).get("main", "main.wasm")
    for name in sorted(os.listdir(ctx.cart_dir)):
        path = os.path.join(ctx.cart_dir, name)
        if os.path.isfile(path) and name not in REPO_FILES:
            shutil.copyfile(path, os.path.join(folder, name))
    with open(os.path.join(folder, main), "wb") as f:
        f.write(wasm)
    return {"wasm": wasm, "pins": {"jet": JET, "jetexamples": EXAMPLES}}
