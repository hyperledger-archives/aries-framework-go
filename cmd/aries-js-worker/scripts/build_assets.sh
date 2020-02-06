#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

GOOS=js GOARCH=wasm go build -o src/aries-js-worker.wasm main.go
gzip -f src/aries-js-worker.wasm
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" src/

rm -rf dist/assets
mkdir -p dist/assets
cp -p src/aries-js-worker.wasm.gz dist/assets
cp -p src/wasm_exec.js dist/assets
