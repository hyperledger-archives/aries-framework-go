#!/bin/bash
#
# Copyright Avast Software. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

go generate ./...

# TODO Support collecting code coverage
# TODO Create containers with libursa installed for local tests and development.
# Current CI uses ghcr.io/hyperledger/ursa-wrapper-go/uwg-build.

 # Running aries-framework-go unit test with ursa
PKGS=$(go list -tags ursa github.com/hyperledger/aries-framework-go/pkg/... 2> /dev/null | grep -v /mocks | grep -v /aries-js-worker)
go test -tags ursa $PKGS -count=1 -race -timeout=10m
