#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

# Running wasm unit test
# TODO Support collecting code coverage  https://github.com/agnivade/wasmbrowsertest/issues/5
# TODO Fail CI if headless chrome isn't available https://github.com/hyperledger/aries-framework-go/issues/843

cd component/storage/indexeddb
PKGS="github.com/hyperledger/aries-framework-go/component/storage/indexeddb"
PATH="$GOBIN:$PATH" GOOS=js GOARCH=wasm go test $PKGS -count=1 -exec=wasmbrowsertest -timeout=10m
cd -

cd cmd/aries-js-worker
PKGS="github.com/hyperledger/aries-framework-go/cmd/aries-js-worker"
PATH="$GOBIN:$PATH" GOOS=js GOARCH=wasm go test $PKGS -count=1 -exec=wasmbrowsertest -timeout=10m
cd -
