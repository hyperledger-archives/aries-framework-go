#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

GOOS=js GOARCH=wasm go build -o src/aries-js-worker.wasm main.go
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" src/
