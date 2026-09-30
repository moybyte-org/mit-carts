# ESP 88

JetExamples' `esp32-neon-film`: a two-minute neon city film in twelve cuts,
drawn by [Jet](https://github.com/CubeCoders/Jet), CubeCoders' software
rasteriser, and played in a loop. MIT, see [LICENSES.txt](LICENSES.txt).

| button | does |
|---|---|
| left / right | the cut before / after, wrapping round the film |
| A | the HUD: the cut, the whole-frame rate and the mean ms Jet took |

| `config.json` key | values | what it is |
|---|---|---|
| `interlaced` | `true`, `false` | one field a frame, as the example plays it, or both |
| `hud` | `false`, `true` | the HUD at launch |
| `cut` | `1`–`12` | the cut it starts at |
| `cores` | `2`, `1` | the raster and the scan-out across the console's cores or on one |

The film's own code builds and animates every cut; the cart plays it from its
own clock. The picture is two thirds of the film's: the 480 × 296 between its
letterbox bars becomes 320 × 198, centred in the console's 320 × 240. The
film's artwork -- textures, palettes, glow and credits -- is `assets.bin`, read
at `_init` into zeroed arrays rather than compiled in as initialised data.

`"memory": 27` pages: a 16 KB stack, the frame, the two half-width fields and
the artwork's arrays, then about 1.25 MB of heap for each cut's city, cars and
cockpit and Jet's per-frame queues. The whole footprint is about 2.7 MB on
either chip, so a board that cannot fit it opens a notice instead.
