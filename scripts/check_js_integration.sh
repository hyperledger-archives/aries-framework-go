#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

ROOT=`pwd`

echo ""
echo "Running aries-js-worker integration tests..."
echo ""
echo "----> packing aries-js-worker"
echo ""
cd $ROOT/cmd/aries-js-worker
npm install
npm link
echo ""
echo "----> setting up aries-js-worker tests"
echo ""
cd $ROOT/test/aries-js-worker
npm install
npm link @hyperledger/aries-framework-go
echo ""
echo "----> starting fixtures"
echo ""
cd $ROOT/test/aries-js-worker/fixtures
docker-compose down --remove-orphans && docker-compose up -d
echo ""
echo "----> executing aries-js-worker tests"
echo ""
cd $ROOT/test/aries-js-worker
command=$1
if [ -z "$command" ]; then
    command=test
fi
# capture exit code if it fails
npm run "$command" || code=$?
if [ -z ${code+x} ]; then
  # set exit code because it did not fail
  code=0
fi
echo ""
echo "----> stopping fixtures"
echo ""
cd $ROOT/test/aries-js-worker/fixtures
docker-compose logs > docker-compose.log
docker-compose stop
cd $ROOT
exit $code
