# Moybyte MIT carts

MIT-licensed carts for [Moybyte](https://github.com/moybyte-org/moybyte)
consoles, compiled ("runtime": "wasm") carts built by recipe. They're free, and
never come preinstalled on a console.

## Install

With [moy](https://github.com/moybyte-org/moy-spec/releases/tag/player-latest):

```
moy install --index https://moybyte-org.github.io/mit-carts/index.json --list
moy install --index https://moybyte-org.github.io/mit-carts/index.json teapot /path/to/sdcard/moybyte/carts
```

From a checkout of this repository, `python3 install.py teapot /path/to/sdcard/moybyte/carts`
does the same (it runs moy's installer with this index). The installer downloads
the cart, checks every file against its hash, and writes a ready cart folder.
For a board without an SD card, install to a folder on your computer and copy
the cart over with Moybyte's `tools/push_cart.py`.

A Moybyte console installs from the same index with its Get Carts app. A
browser cannot read a GitHub release download (it sends no CORS header), so
the index also names a **mirror** of each release asset on this repository's
Pages site, `releases/<tag>/<asset>`, which a browser console reads instead.
The release stays the canonical copy.

## Carts

| | cart | notes |
|---|---|---|
| ![Jet Teapot](carts/teapot/cover.png) | [Jet Teapot](carts/teapot/) | The Utah teapot, lit and depth-buffered, with the camera yours. Runs on every console board. |
| ![ESP 88](carts/esp88/cover.png) | [ESP 88](carts/esp88/) | A two-minute neon city film in twelve cuts, played in a loop. Needs about 2.7 MB, so a board that cannot fit it shows a notice. |

Each picture is the cart's `cover.png`, the one a console's store and shelf
show (moy-spec's SPEC.md 3.6). The index points at it on this site, so a new
cover shows without a new release; the next release carries it in the cart too.

## Credits

Jet, JetExamples and the scenes these carts port are by
[CubeCoders](https://github.com/CubeCoders/Jet) (PhonicUK).

## Source and licence

This repository is MIT ([LICENSE](LICENSE)); each cart's `LICENSES.txt` says
whose each part is. A cart is built by `scripts/build.py`, which runs its
recipe with Moybyte's Jet build (`tools/jet_cart.py` at a pinned moybyte
commit), compiles a module per chip and packs the release: the cart, and its
whole source as one archive. Moybyte keeps a stamped copy of each cart's folder
for its own tests and on-glass guards (its `ports/jet/`); this repository is
where the carts change.

```
python3 scripts/build.py teapot --unsigned -o ~/teapot-build
python3 install.py teapot /path/to/sdcard/moybyte/carts --build ~/teapot-build
python3 scripts/build.py teapot --verify-release teapot.moy.zip teapot-v3-source.tar.gz
```

`--verify-release` rebuilds the cart from the checkout it runs in, so check a
release from the commit it was built from (the index's `build.commit`).

Only maintainers can sign a release. A cart you built yourself is unsigned, so
turn on Unknown sources in the console's Settings to run it.

The Pages site -- `index.json`, the covers, the licence texts and the
mirrors -- is deployed by `.github/workflows/pages.yml` once `validate` has
passed on the default branch or on a published release. `scripts/pages.py`
downloads each release asset the index names and checks it against the
index's size and sha256 before the site is built; an index ahead of its
release leaves the site as it was until the release is published.
`scripts/make_index.py` writes the index, mirrors included.
