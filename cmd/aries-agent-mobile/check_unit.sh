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

PKGS=$(go list github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile... 2> /dev/null)
$GO_TEST_CMD $PKGS -coverprofile=profile.out -count=1 -race -timeout=10m -cover
amend_coverage_file
