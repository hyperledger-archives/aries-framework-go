#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

GO_TEST_CMD="go test"

go generate ./...
ROOT=$(pwd)
echo "" > "$ROOT"/coverage.txt

amend_coverage_file () {
if [ -f profile.out ]; then
     cat profile.out >> "$ROOT"/coverage.txt
     rm profile.out
fi
}

# docker rm returns 1 if the image isn't found. This is OK and expected, so we suppress it.
remove_docker_container () {
  echo "Removing CouchDBStoreTest docker image..."
  docker kill CouchDBStoreTest >/dev/null 2>&1 || true
  docker rm CouchDBStoreTest >/dev/null 2>&1 || true
  echo "Removing MYSQLStoreTest docker image..."
  docker kill MYSQLStoreTest >/dev/null 2>&1 || true
  docker rm MYSQLStoreTest >/dev/null 2>&1 || true
}

cleanup() {
  remove_docker_container
}

trap cleanup EXIT

if [ -z ${SKIP_DOCKER+x} ]; then
  remove_docker_container

  echo "Starting CouchDBStoreTest docker image..."
  docker run -p 5984:5984 -d --name CouchDBStoreTest \
             -v $ROOT/scripts/couchdb-config/10-single-node.ini:/opt/couchdb/etc/local.d/10-single-node.ini \
             -e COUCHDB_USER=admin -e COUCHDB_PASSWORD=password couchdb:3.1.0 >/dev/null
  echo "Starting MYSQLStoreTest docker image..."
  docker run -p 3306:3306 -d --name MYSQLStoreTest \
             -e MYSQL_ROOT_PASSWORD=my-secret-pw mysql:8.0.20 >/dev/null
else
  GO_TEST_CMD="$GO_TEST_CMD --tags=ISSUE2183"
fi

# Running aries-framework-go unit test
PKGS=$(go list github.com/hyperledger/aries-framework-go/... 2> /dev/null | grep -v /mocks | grep -v /aries-js-worker)
$GO_TEST_CMD $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file

# Running aries-agent-rest unit test
cd cmd/aries-agent-rest
PKGS=$(go list github.com/hyperledger/aries-framework-go/cmd/aries-agent-rest/... 2> /dev/null | grep -v /mocks)
$GO_TEST_CMD $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$ROOT" || exit
