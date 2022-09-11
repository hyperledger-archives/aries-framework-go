#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running aries-framework-go integration tests..."
PWD=`pwd`
cd test/bdd
go test -count=1 -v -cover . -p 1 -timeout=45m -race
go test -count=1 -v -cover . -p 1 -timeout=30m -race -run present_proof_controller,issue_credential,issue_credential_controller,webkms,waci_issuance,verifiable,verifiable_jwt
go test -count=1 -v -cover . -p 1 -timeout=30m -race -run presentproof
go test -count=1 -v -cover . -p 1 -timeout=30m -race -run didcomm_remote_crypto,outofbandv2
go test -count=1 -v -cover . -p 1 -timeout=45m -race -run outofband
DEFAULT_KEY_TYPE="ecdsap256ieee1363" DEFAULT_KEY_AGREEMENT_TYPE="p256kw" go test -count=1 -v -cover . -p 1 -timeout=10m -race -run didcommv2
CARL_MEDIA_TYPE_PROFILES="didcomm/aip1" CARL_KEYAGREEMENT_TYPE="X25519ECDHKW" DAVE_MEDIA_TYPE_PROFILES="didcomm/aip2;env=rfc19" DAVE_KEYAGREEMENT_TYPE="X25519ECDHKW" go test -count=1 -v -cover . -p 1 -timeout=20m -race -run aries_router_controller

cd $PWD


