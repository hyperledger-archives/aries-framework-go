#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

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
docker kill AriesMongoDBStorageTest >/dev/null 2>&1 || DOCKER_KILL_EXIT_CODE=$?
docker kill AriesEDVStorageTest >/dev/null 2>&1 || DOCKER_KILL_EXIT_CODE=$?

check_exit_code $DOCKER_KILL_EXIT_CODE "docker kill AriesMongoDBStorageTest"
check_exit_code $DOCKER_KILL_EXIT_CODE "docker kill AriesEDVStorageTest"

DOCKER_RM_EXIT_CODE=0
docker rm AriesMongoDBStorageTest >/dev/null 2>&1 || DOCKER_RM_EXIT_CODE=$?
docker rm AriesEDVStorageTest >/dev/null 2>&1 || DOCKER_RM_EXIT_CODE=$?

check_exit_code $DOCKER_RM_EXIT_CODE "docker rm AriesMongoDBStorageTest"
check_exit_code $DOCKER_RM_EXIT_CODE "docker rm AriesEDVStorageTest"
}

DOCKER_CREATE_NETWORK_EXIT_CODE=0
docker network create AriesTestNetwork >/dev/null 2>&1 || DOCKER_CREATE_NETWORK_EXIT_CODE=$?
check_exit_code $DOCKER_CREATE_NETWORK_EXIT_CODE "docker network create AriesTestNetwork"

remove_docker_containers

PWD=$(pwd)

docker run -p 27017:27017 -d --network AriesTestNetwork --name AriesMongoDBStorageTest mongo:4.0.0 >/dev/null

docker run -p 8071:8071 -d --network AriesTestNetwork --name AriesEDVStorageTest ghcr.io/trustbloc-cicd/edv:0.1.9-snapshot-894c500 start --host-url 0.0.0.0:8071 --database-prefix edv_db_ --database-type mongodb --database-url mongodb://AriesMongoDBStorageTest:27017 --with-extensions Batch --log-level=debug >/dev/null
