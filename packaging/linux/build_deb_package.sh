#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "============================================================"
echo "Building Vajra Debian Package (.deb)"
echo "============================================================"

# 1. Ensure release binaries are built
if [[ ! -f "$ROOT_DIR/target/release/vajra-cli" || ! -f "$ROOT_DIR/target/release/vajra-verify" ]]; then
    echo "[+] Compiling release binaries in Rust workspace..."
    cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml" -p vajra-cli -p vajra-verify
fi

# 2. Prepare staging directory layout in /tmp for proper POSIX permission control
PKG_DIR="/tmp/vajra_0.1.0_amd64"
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/share/vajra/config"
mkdir -p "$PKG_DIR/usr/share/vajra/ml-models"
mkdir -p "$PKG_DIR/usr/share/doc/vajra"

# 3. Copy binaries and assets
cp "$ROOT_DIR/target/release/vajra-cli" "$PKG_DIR/usr/bin/vajra-cli"
cp "$ROOT_DIR/target/release/vajra-verify" "$PKG_DIR/usr/bin/vajra-verify"
chmod 755 "$PKG_DIR/usr/bin/vajra-cli" "$PKG_DIR/usr/bin/vajra-verify"

cp "$ROOT_DIR/config/signatures.json" "$PKG_DIR/usr/share/vajra/config/"
cp "$ROOT_DIR/ml-models/file_type_classifier_trees.json" "$PKG_DIR/usr/share/vajra/ml-models/"
cp "$ROOT_DIR/ml-models/model_metadata.json" "$PKG_DIR/usr/share/vajra/ml-models/"
cp "$ROOT_DIR/README.md" "$PKG_DIR/usr/share/doc/vajra/"

# 4. Copy and set permissions for maintainer scripts
cp "$SCRIPT_DIR/debian/control" "$PKG_DIR/DEBIAN/"
cp "$SCRIPT_DIR/debian/preinst" "$PKG_DIR/DEBIAN/"
cp "$SCRIPT_DIR/debian/postinst" "$PKG_DIR/DEBIAN/"
chmod 755 "$PKG_DIR/DEBIAN"
chmod 755 "$PKG_DIR/DEBIAN/preinst" "$PKG_DIR/DEBIAN/postinst"
chmod 644 "$PKG_DIR/DEBIAN/control"

# 5. Build Debian package via dpkg-deb
OUT_DEB="$ROOT_DIR/target/release/vajra_0.1.0_amd64.deb"
mkdir -p "$ROOT_DIR/target/release"
dpkg-deb --build "$PKG_DIR" "$OUT_DEB"
rm -rf "$PKG_DIR"

echo "============================================================"
echo "[✓] Debian Package Built Successfully: $OUT_DEB"
echo "============================================================"
