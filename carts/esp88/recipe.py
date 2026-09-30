# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Nikola Jovicic
"""The recipe for this cart: scripts/jet_recipe.py, which builds it with
Moybyte's tools/jet_cart.py at the moybyte commit scripts/build.py pins."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "scripts"))

import jet_recipe  # noqa: E402


def build(ctx, folder):
    return jet_recipe.build(ctx, folder)
