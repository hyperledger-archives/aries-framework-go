#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

# TODO: MacOS Monterey Golang fix, remove "MallocNanoZone=0" once https://github.com/golang/go/issues/49138 is resolved.
# TODO: issue is now resolved in :https://github.com/golang/go/commit/5f6552018d1ec920c3ca3d459691528f48363c3c,
# TODO" but will need to wait for next Go release.
export MallocNanoZone=0

echo "Running $0"

# Running wasm unit test
# TODO Support collecting code coverage  https://github.com/agnivade/wasmbrowsertest/issues/5
# TODO Fail CI if headless chrome isn't available https://github.com/hyperledger/aries-framework-go/issues/843

PKGS="github.com/hyperledger/aries-framework-go/component/storage/indexeddb
github.com/hyperledger/aries-framework-go/cmd/aries-js-worker"

cd cmd/aries-js-worker
PATH="$GOBIN:$PATH" GOOS=js GOARCH=wasm go test $PKGS -count=1 -exec=wasmbrowsertest -cover -timeout=10m

