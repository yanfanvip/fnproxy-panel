#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p build

echo "Building Linux executable..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go -C src build -trimpath -o ../build/fnproxy-panel-linux-amd64 .

echo "Build completed: build/fnproxy-panel-linux-amd64"
