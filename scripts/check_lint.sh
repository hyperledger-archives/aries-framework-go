#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Running $0"

DOCKER_CMD=${DOCKER_CMD:-docker}
GOLANGCI_LINT_IMAGE="golangci/golangci-lint:v1.31.0"

if [ ! $(command -v ${DOCKER_CMD}) ]; then
    exit 0
fi

${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace ${GOLANGCI_LINT_IMAGE} golangci-lint run
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY}  -e GOOS=js -e GOARCH=wasm -v $(pwd):/opt/workspace -w /opt/workspace ${GOLANGCI_LINT_IMAGE} golangci-lint run
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/cmd/aries-agent-rest ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/cmd/aries-agent-mobile ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/test/bdd ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/component/newstorage/mem ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../../.golangci.yml
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/test/newstorage/ ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
