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

# TODO (#3421): Update the BBS interop tests to support latest Go and Node versions.

# capture exit code if it fails
npm run test || code=$?
if [ -z ${code+x} ]; then
  # set exit code because it did not fail
  code=0
fi
echo ""
cd $ROOT
exit $code
