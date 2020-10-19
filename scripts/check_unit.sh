#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

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

# Running aries-framework-go unit test
PKGS=$(go list github.com/hyperledger/aries-framework-go/... 2> /dev/null | grep -v /mocks | grep -v /aries-js-worker)
$GO_TEST_CMD $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file

# Running aries-agent-rest unit test
cd cmd/aries-agent-rest
PKGS=$(go list github.com/hyperledger/aries-framework-go/cmd/aries-agent-rest/... 2> /dev/null | grep -v /mocks)
$GO_TEST_CMD $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$ROOT" || exit
