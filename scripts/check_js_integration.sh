#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

ROOT=`pwd`

echo "Running aries-js-worker integration tests..."
echo "----> packing aries-js-worker"
cd $ROOT/cmd/aries-js-worker
npm install
npm link
echo "----> setting up aries-js-worker tests"
cd $ROOT/test/aries-js-worker
npm install
npm link @hyperledger/aries-framework-go
echo "----> executing aries-js-worker tests"
npm test
