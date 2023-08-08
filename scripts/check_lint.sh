#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Running $0"

DOCKER_CMD=${DOCKER_CMD:-docker}
GOLANGCI_LINT_IMAGE="golangci/golangci-lint:v1.53.3"
SHARED_OPTS="--rm --security-opt seccomp=unconfined -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace"

if [ ! $(command -v ${DOCKER_CMD}) ]; then
    exit 0
fi

echo "linting root directory.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace ${GOLANGCI_LINT_IMAGE} golangci-lint run
echo "done linting root directory"
echo "linting with js/wasm.."
${DOCKER_CMD} run ${SHARED_OPTS} -e GOOS=js -e GOARCH=wasm -w /opt/workspace ${GOLANGCI_LINT_IMAGE} golangci-lint run
echo "done linting with js/wasm"
echo "linting cmd/aries-agent-rest.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace/cmd/aries-agent-rest ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting cmd/aries-agent-rest"
echo "linting cmd/aries-agent-mobile.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace/cmd/aries-agent-mobile ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting cmd/aries-agent-mobile"
echo "linting test/bdd.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace/test/bdd ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting test/bdd"

echo "Done Running $0"
