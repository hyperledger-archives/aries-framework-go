#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

# TODO: MacOS Monterey Golang fix, remove "MallocNanoZone=0" once https://github.com/golang/go/issues/49138 is resolved.
# TODO: issue is now resolved in :https://github.com/golang/go/commit/5f6552018d1ec920c3ca3d459691528f48363c3c,
# TODO" but will need to wait for next Go release.
export MallocNanoZone=0

echo "Running $0"

GO_TEST_CMD="go test"

go generate ./...
ROOT=$(pwd)
touch "$ROOT"/coverage.out

amend_coverage_file () {
if [ -f profile.out ]; then
     cat profile.out >> "$ROOT"/coverage.out
     rm profile.out
fi
}

# First argument is the exit code.
# Second argument is the command that was run.
check_exit_code () {
if [ "$1" -ne 0 ] && [ "$1" -ne 1 ]; then
  echo "error: '${2}' returned ${1}, but either 0 or 1 was expected."

  # There's no easy way to print the error message on the screen without temporary files,
  # so we ask the user to check manually
  echo "Try running '${2}' manually to see the full error message."

  exit 1
fi
}

# docker rm returns 1 if the container isn't found. This is OK and expected, so we suppress it.
# Any return status other than 0 or 1 is unusual and so we exit.
remove_docker_containers () {
DOCKER_KILL_EXIT_CODE=0
docker kill AriesCouchDBStorageTest >/dev/null 2>&1 || DOCKER_KILL_EXIT_CODE=$?
docker kill AriesEDVStorageTest >/dev/null 2>&1 || DOCKER_KILL_EXIT_CODE=$?

check_exit_code $DOCKER_KILL_EXIT_CODE "docker kill AriesCouchDBStorageTest"
check_exit_code $DOCKER_KILL_EXIT_CODE "docker kill AriesEDVStorageTest"

DOCKER_RM_EXIT_CODE=0
docker rm AriesCouchDBStorageTest >/dev/null 2>&1 || DOCKER_RM_EXIT_CODE=$?
docker rm AriesEDVStorageTest >/dev/null 2>&1 || DOCKER_RM_EXIT_CODE=$?

check_exit_code $DOCKER_RM_EXIT_CODE "docker rm AriesCouchDBStorageTest"
check_exit_code $DOCKER_RM_EXIT_CODE "docker rm AriesEDVStorageTest"
}

# Running aries-framework-go unit test
PKGS=$(go list github.com/hyperledger/aries-framework-go/pkg/... 2> /dev/null | grep -v /mocks | grep -v /aries-js-worker)
$GO_TEST_CMD $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file

# Running aries-agent-rest unit test
cd cmd/aries-agent-rest
PKGS=$(go list github.com/hyperledger/aries-framework-go/cmd/aries-agent-rest/... 2> /dev/null | grep -v /mocks)
$GO_TEST_CMD $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file

# Running storageutil unit tests
cd ../../component/storageutil
PKGS=$(go list github.com/hyperledger/aries-framework-go/component/storageutil/... 2> /dev/null)
$GO_TEST_CMD $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file

# Running storage/leveldb unit tests
cd ../storage/leveldb/
PKGS=$(go list github.com/hyperledger/aries-framework-go/component/storage/leveldb/... 2> /dev/null)
$GO_TEST_CMD $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file

if [ "$SKIP_DOCKER" = true ]; then
    echo "Skipping edv unit tests"
else
  # Running storage/edv unit tests
  cd ../../..

  . "$ROOT"/scripts/start_edv_test_docker_images.sh

  cd component/storage/edv
  PKGS=$(go list github.com/hyperledger/aries-framework-go/component/storage/edv/... 2> /dev/null)
  GO_TEST_EXIT_CODE=0
  $GO_TEST_CMD $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m  || GO_TEST_EXIT_CODE=$?
  if [ $GO_TEST_EXIT_CODE -ne 0 ]; then
    docker kill CouchDBStoreTest >/dev/null
    docker kill MySQLStoreTest >/dev/null
    remove_docker_containers

    exit $GO_TEST_EXIT_CODE
  fi

amend_coverage_file

docker kill AriesCouchDBStorageTest >/dev/null
docker kill AriesEDVStorageTest >/dev/null
remove_docker_containers
fi


cd "$ROOT" || exit
