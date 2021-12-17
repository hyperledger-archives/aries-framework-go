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

GO_TEST_CMD="go test"

go generate ./...
ROOT=$(pwd)
touch "$ROOT"/coverage.out

amend_coverage_file () {
if [ -f profile.out ]; then
     cat profile.out >> "$ROOT"/coverage.out
     rm profile.out
fi
}

PKGS=$(go list github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile... 2> /dev/null)
$GO_TEST_CMD $PKGS -coverprofile=profile.out -count=1 -race -timeout=10m -cover
amend_coverage_file
