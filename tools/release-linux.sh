#!/usr/bin/env bash
# Linux release: tests, release build, package, SHA256SUMS.txt, tar.gz + archive hash.
# Steps follow BUILD.md. Run from the repository root; needs Rust >= 1.83 and gcc.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

cargo test --locked
cargo build --release --locked

rm -rf package && cp -r dist/linux package
cp target/release/netfreedom package/netfreedom
chmod 755 package/netfreedom
cp LICENSE THIRD-PARTY-NOTICES.md PHILOSOPHY.md README.md package/
rm -f package/SHA256SUMS.txt

( cd package
  find . -type f ! -name SHA256SUMS.txt | sed 's|^\./||' | LC_ALL=C sort | \
    while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done > SHA256SUMS.txt
  sha256sum -c --quiet SHA256SUMS.txt && echo "package checksums OK" )

ARCHIVE="NetFreedom-${VERSION}-linux-x64.tar.gz"
tar -C package -czf "$ARCHIVE" .
sha256sum "$ARCHIVE" | tee "$ARCHIVE.sha256"
./package/netfreedom verify
