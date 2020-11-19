#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

ROOT=`pwd`

echo ""
echo "Running BBS+ interoperability tests..."
cd $ROOT/test/bbs
command=$1
if [ -z "$command" ]; then
    command=test
fi

npm install

cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" src/

# capture exit code if it fails
npm run test || code=$?
if [ -z ${code+x} ]; then
  # set exit code because it did not fail
  code=0
fi
echo ""
cd $ROOT
exit $code
