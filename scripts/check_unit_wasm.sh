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

PKGS="github.com/hyperledger/aries-framework-go/pkg/storage/jsindexeddb
github.com/hyperledger/aries-framework-go/cmd/aries-js-worker"

cd cmd/aries-js-worker
PATH="$GOBIN:$PATH" GOOS=js GOARCH=wasm go test $PKGS -count=1 -exec=wasmbrowsertest -cover -timeout=10m

