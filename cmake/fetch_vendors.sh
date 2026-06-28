#!/bin/bash
# fetch_vendors.sh -- Download vendored dependencies for EDP
# Run once from the edp/ directory before building.
# Hydrogenuine / Project DOCS -- MIT License

set -euo pipefail

VENDOR_DIR="$(cd "$(dirname "$0")/.." && pwd)/vendor"
mkdir -p "$VENDOR_DIR"

echo "Fetching BLAKE3..."
BLAKE3_VERSION="1.5.4"
BLAKE3_BASE="https://raw.githubusercontent.com/BLAKE3-team/BLAKE3/refs/tags/${BLAKE3_VERSION}/c"
curl -fsSL "$BLAKE3_BASE/blake3.h"          -o "$VENDOR_DIR/blake3.h"
curl -fsSL "$BLAKE3_BASE/blake3.c"          -o "$VENDOR_DIR/blake3.c"
curl -fsSL "$BLAKE3_BASE/blake3_portable.c" -o "$VENDOR_DIR/blake3_portable.c"
curl -fsSL "$BLAKE3_BASE/blake3_impl.h"     -o "$VENDOR_DIR/blake3_impl.h"
echo "  BLAKE3 ${BLAKE3_VERSION} -> vendor/"

echo "Fetching Monocypher..."
MONO_VERSION="4.0.2"
MONO_BASE="https://raw.githubusercontent.com/LoupVaillant/Monocypher/${MONO_VERSION}/src"
curl -fsSL "$MONO_BASE/monocypher.h" -o "$VENDOR_DIR/monocypher.h"
curl -fsSL "$MONO_BASE/monocypher.c" -o "$VENDOR_DIR/monocypher.c"
echo "  Monocypher ${MONO_VERSION} -> vendor/"

echo "Vendor fetch complete."
echo "Licenses:"
echo "  BLAKE3:     CC0-1.0 / Apache-2.0"
echo "  Monocypher: BSD-2-Clause"
