#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

rm -rf public/aries-framework-go
cp -Rp node_modules/@hyperledger/aries-framework-go/ public
gunzip public/aries-framework-go/dist/assets/aries-js-worker.wasm.gz
vue-cli-service serve
