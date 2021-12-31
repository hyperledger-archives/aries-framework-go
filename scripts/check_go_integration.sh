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

echo "Running aries-framework-go integration tests..."
PWD=`pwd`
cd test/bdd
go test -count=1 -v -cover . -p 1 -timeout=45m -race
go test -count=1 -v -cover . -p 1 -timeout=20m -race -run presentproof,present_proof_controller,issue_credential,issue_credential_controller,webkms
DEFAULT_KEY_TYPE="ecdsap256ieee1363" DEFAULT_KEY_AGREEMENT_TYPE="p256kw" go test -count=1 -v -cover . -p 1 -timeout=10m -race -run didcommv2
CARL_MEDIA_TYPE_PROFILES="didcomm/aip1" CARL_KEYAGREEMENT_TYPE="X25519ECDHKW" DAVE_MEDIA_TYPE_PROFILES="didcomm/aip2;env=rfc19" DAVE_KEYAGREEMENT_TYPE="X25519ECDHKW" go test -count=1 -v -cover . -p 1 -timeout=20m -race -run aries_router_controller
CARL_MEDIA_TYPE_PROFILES="didcomm/aip2;env=rfc587" CARL_KEYAGREEMENT_TYPE="X25519ECDHKW" DAVE_MEDIA_TYPE_PROFILES="didcomm/v2" DAVE_KEYAGREEMENT_TYPE="X25519ECDHKW" go test -count=1 -v -cover . -p 1 -timeout=20m -race -run aries_router_controller

cd $PWD


