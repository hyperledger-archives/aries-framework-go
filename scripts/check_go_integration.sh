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
go test -count=1 -v -cover . -p 1 -timeout=20m -race
go test -count=1 -v -cover . -p 1 -timeout=20m -race -run presentproof present_proof_controller
cd $PWD


