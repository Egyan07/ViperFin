#!/bin/bash
# Build script for viperfin
# Produces binaries for Linux, Windows, and macOS (amd64 + arm64)

set -e

BINARY="viperfin"
VERSION="1.0.0"
BUILD_DIR="./build"

echo "Building viperfin v${VERSION}..."
mkdir -p "$BUILD_DIR"

targets=(
  "linux   amd64 ${BINARY}-linux-amd64"
  "linux   arm64 ${BINARY}-linux-arm64"
  "windows amd64 ${BINARY}-windows-amd64.exe"
  "darwin  amd64 ${BINARY}-darwin-amd64"
  "darwin  arm64 ${BINARY}-darwin-arm64"
)

count=1
total=${#targets[@]}

for entry in "${targets[@]}"; do
  read -r os arch outname <<< "$entry"
  echo "[${count}/${total}] Building ${os}/${arch}..."
  GOOS="$os" GOARCH="$arch" go build \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o "${BUILD_DIR}/${outname}" .
  echo "      -> ${BUILD_DIR}/${outname}"
  (( count++ ))
done

echo ""
echo "Done. Binaries in ${BUILD_DIR}/"
echo ""
echo "Quick test (Linux):"
echo "  ./${BUILD_DIR}/${BINARY}-linux-amd64 client google.com:443"
echo "  ./${BUILD_DIR}/${BINARY}-linux-amd64 server --port 4443"
echo "  ./${BUILD_DIR}/${BINARY}-linux-amd64 lookup --list"
