#!/bin/bash
set -e

VERSION="0.1.0"
OUT_DIR="./bin"

echo "Building NoorSigner v${VERSION}..."

mkdir -p "$OUT_DIR"

# macOS (ARM64)
echo "Building macOS ARM64..."
GOOS=darwin GOARCH=arm64 go build -o "$OUT_DIR/noorsigner-macos-arm64" -ldflags="-s -w" .

# macOS (AMD64)
echo "Building macOS AMD64..."
GOOS=darwin GOARCH=amd64 go build -o "$OUT_DIR/noorsigner-macos-amd64" -ldflags="-s -w" .

# Linux (AMD64)
echo "Building Linux AMD64..."
GOOS=linux GOARCH=amd64 go build -o "$OUT_DIR/noorsigner-linux-amd64" -ldflags="-s -w" .

# Linux (ARM64)
echo "Building Linux ARM64..."
GOOS=linux GOARCH=arm64 go build -o "$OUT_DIR/noorsigner-linux-arm64" -ldflags="-s -w" .

echo "Build complete! Binaries in $OUT_DIR"
ls -lh "$OUT_DIR"
