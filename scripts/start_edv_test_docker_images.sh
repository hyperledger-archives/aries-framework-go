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

DOCKER_CREATE_NETWORK_EXIT_CODE=0
docker network create AriesTestNetwork >/dev/null 2>&1 || DOCKER_CREATE_NETWORK_EXIT_CODE=$?
check_exit_code $DOCKER_CREATE_NETWORK_EXIT_CODE "docker network create AriesTestNetwork"

remove_docker_containers

PWD=$(pwd)
configPath="$PWD"/scripts/couchdb-config/10-single-node.ini
docker run -p 5984:5984 -d --network AriesTestNetwork --name AriesCouchDBStorageTest -v "$configPath":/opt/couchdb/etc/local.d/config.ini -e COUCHDB_USER=admin -e COUCHDB_PASSWORD=password couchdb:3.1.0 >/dev/null

docker run -p 8071:8071 -d --network AriesTestNetwork --name AriesEDVStorageTest ghcr.io/trustbloc-cicd/edv:0.1.6-snapshot-0f1daba start --host-url 0.0.0.0:8071 --database-prefix edv_db_ --database-type couchdb --database-url admin:password@AriesCouchDBStorageTest:5984 --with-extensions ReturnFullDocumentsOnQuery,Batch  >/dev/null
