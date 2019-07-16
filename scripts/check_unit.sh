#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

# Packages to exclude
PKGS=`go list github.com/hyperledger/aries-framework-go/... 2> /dev/null | \
                                                 grep -v /mocks`

go generate ./...

go test $PKGS -count=1 -race -coverprofile=coverage.txt -covermode=atomic  -p 1 -timeout=10m
