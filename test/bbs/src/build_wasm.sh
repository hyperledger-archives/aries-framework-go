#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

cd src
GOOS=js GOARCH=wasm go build -o bbs.wasm *.go
cd ..
