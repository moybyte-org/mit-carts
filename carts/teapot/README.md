# Jet Teapot

The Utah teapot from JetExamples' `esp32-lighting-teapot` -- its light, glaze,
sky gradient, rocking motion and Flat / Gouraud / Phong cycle -- drawn by
[Jet](https://github.com/CubeCoders/Jet), CubeCoders' software rasteriser, with
the camera yours. MIT, see [LICENSES.txt](LICENSES.txt).

| button | does |
|---|---|
| left / right | turn |
| up / down | fly forward / back, level |
| A / B | climb / sink |

The HUD's strip reads the width, the shading, the whole-frame rate, the mean
time Jet's `render()` took, and the triangles it rasterized, each averaged over
the last second. `config.json` picks how the frame is made, at launch:

| key | values | what it is |
|---|---|---|
| `width` | `"full"`, `"half"` | Jet's `HALF_WIDTH_BUFFERS`: one stored pixel per two columns, doubled into the frame |
| `interlaced` | `false`, `true` | Jet's `interlacedMode`: each frame renders every other row, alternating |
| `shading` | `"cycle"`, `"flat"`, `"gouraud"`, `"phong"` | the example's three-second cycle, or one mode held |
| `hud` | `true`, `false` | the HUD in the frame's top strip |
| `cores` | `2`, `1` | the raster across the console's cores or on one |

A Phong-lit surface is a gradient, which a 256-entry palette would have to
quantize, so the frame goes to the console whole through `blit565`. Half width
is a compile-time switch in Jet, so the module carries Jet twice and the cart
picks one at `_init`. The raster is cut into bands the console runs across its
cores (`par`), the frame's setup staying on one, as Jet's own ESP32-S3 runtime
does.

`"memory": 13` pages: a 64 KB stack, the frame and Jet's depth buffer, then
the heap, which holds the model while Jet's loader parses it and Jet's
per-frame queues. `src/` is the port: `main.cpp` (hooks, buttons, config, HUD),
`scene.cpp` (the example's scene, compiled once per Jet build), `runtime.cpp`
(the heap, `par`'s items and the C library's edges), `moy_cart.h` (moy-spec's
imports). `teapot.obj` is the example's generated mesh as an OBJ, read through
`read` and Jet's own loader.
