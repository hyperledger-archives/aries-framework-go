#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running aries-framework-go Verifiable Credential test suite..."

GENERATOR_NAME=aries-framework-go-gen
VC_TEST_SUITE=vc-test-suite
REPORT_NAME=aries-framework-go
DIR=$(pwd)
GENERATOR_DIR="${DIR}/component/models/verifiable/test-suite"

BUILD_DIR="${DIR}/build"
SUITE_DIR="${BUILD_DIR}/${VC_TEST_SUITE}/suite"

# build the app to test
cd $GENERATOR_DIR
# rename test file in order to be able to build it
rm -rf tmp
mkdir tmp
cp verifiable_suite_test.go tmp/vc_test_suite_app.go
cp -R contexts tmp/
cd tmp
go build -tags testsuite -o "${BUILD_DIR}/${VC_TEST_SUITE}/${GENERATOR_NAME}"
cd ..
rm -rf tmp
cd "${BUILD_DIR}/${VC_TEST_SUITE}"
export PATH=$PATH:`pwd`

# get the suite
rm -rf ${SUITE_DIR}
git clone --depth=1 -q https://github.com/w3c/vc-test-suite suite

# build the suite
cd ${SUITE_DIR}
npm install
cp "${GENERATOR_DIR}/config.json" .

# patch JWS test input data (as long as https://github.com/w3c/vc-test-suite/issues/103 is opened)
cp "${GENERATOR_DIR}/vc_jwt.patch" .
git apply vc_jwt.patch

chmod 754 ../aries-framework-go-gen

# run the suite
set +e
./node_modules/.bin/mocha --recursive --timeout 10000 test/vc-data-model-1.0/ -R json > "implementations/${REPORT_NAME}-report.json"

sed '/\"tests\": \[/,$d' < "implementations/${REPORT_NAME}-report.json" > ${BUILD_DIR}/${VC_TEST_SUITE}/summary.json
echo "}" >> ${BUILD_DIR}/${VC_TEST_SUITE}/summary.json

echo "Test suite summary:"
cat ${BUILD_DIR}/${VC_TEST_SUITE}/summary.json
echo "See full test suite results at ${SUITE_DIR}/implementations/${REPORT_NAME}-report.json"

cd $DIR

echo
if grep -q "\"failures\": 0" ${BUILD_DIR}/${VC_TEST_SUITE}/summary.json; then
  echo "Verifiable Credential test suite passed!"
  exit 0
else
  echo "Verifiable Credential test suite did not pass"
  exit 1
fi
