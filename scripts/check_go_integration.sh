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
go test -count=1 -v -cover . -p 1 -timeout=20m -race
go test -count=1 -v -cover . -p 1 -timeout=20m -race -run presentproof,present_proof_controller,issue_credential,issue_credential_controller
CARL_MEDIA_TYPE_PROFILES="didcomm/aip1" CARL_KEYAGREEMENT_TYPE="X25519ECDHKW" DAVE_MEDIA_TYPE_PROFILES="didcomm/aip2;env=rfc19" DAVE_KEYAGREEMENT_TYPE="X25519ECDHKW" go test -count=1 -v -cover . -p 1 -timeout=20m -race -run aries_router_controller
CARL_MEDIA_TYPE_PROFILES="didcomm/aip2;env=rfc587" CARL_KEYAGREEMENT_TYPE="X25519ECDHKW" DAVE_MEDIA_TYPE_PROFILES="didcomm/v2" DAVE_KEYAGREEMENT_TYPE="X25519ECDHKW" go test -count=1 -v -cover . -p 1 -timeout=20m -race -run aries_router_controller
# TODO currently, agents with incompatible media type profiles and key agreement type can't communicate due to mismatching key types (can't pack DIDComm V1 msg using ED25519 key with DIDcomm V2 compatible keys such as X25519KW or NISTP384KW key, and vice versa).
#CARL_MEDIA_TYPE_PROFILES="didcomm/v2" CARL_KEYAGREEMENT_TYPE="X25519ECDHKW" DAVE_MEDIA_TYPE_PROFILES="didcomm/aip2;env=rfc19" DAVE_KEYAGREEMENT_TYPE="X25519ECDHKW" go test -count=1 -v -cover . -p 1 -timeout=20m -race -run aries_router_controller

cd $PWD


