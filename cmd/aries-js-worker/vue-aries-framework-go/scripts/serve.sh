#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

cd ..
npm link
cd vue-aries-framework-go
npm link @hyperledger/aries-framework-go
rm -rf public/aries-framework-go
mkdir -p public/aries-framework-go/assets
cp -Rp node_modules/@hyperledger/aries-framework-go/dist/assets/* public/aries-framework-go/assets
gunzip public/aries-framework-go/assets/aries-js-worker.wasm.gz
vue-cli-service serve
