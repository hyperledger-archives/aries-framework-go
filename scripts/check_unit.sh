#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

go generate ./...
pwd=`pwd`
echo "" > "$pwd"/coverage.txt

amend_coverage_file () {
if [ -f profile.out ]; then
     cat profile.out >> "$pwd"/coverage.txt
     rm profile.out
fi
}

# docker rm returns 1 if the image isn't found. This is OK and expected, so we suppress it
# Any return status other than 0 or 1 is unusual and so we exit
remove_docker_container () {
docker kill CouchDBStoreTest >/dev/null 2>&1 || true
docker rm CouchDBStoreTest >/dev/null 2>&1 || true
}

remove_docker_container

docker run -p 5984:5984 -d --name CouchDBStoreTest couchdb:2.3.1 >/dev/null || true


# Running aries-framework-go unit test
PKGS=`go list github.com/hyperledger/aries-framework-go/... 2> /dev/null | \
                                                 grep -v /mocks | \
                                                 grep -v /aries-js-worker`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file

remove_docker_container

# Running aries-agent-rest unit test
cd cmd/aries-agent-rest
PKGS=`go list github.com/hyperledger/aries-framework-go/cmd/aries-agent-rest/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd" || exit
