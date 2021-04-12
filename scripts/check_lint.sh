#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Running $0"

DOCKER_CMD=${DOCKER_CMD:-docker}
GOLANGCI_LINT_IMAGE="golangci/golangci-lint:v1.39.0"

if [ ! $(command -v ${DOCKER_CMD}) ]; then
    exit 0
fi

echo "linting root directory.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace ${GOLANGCI_LINT_IMAGE} golangci-lint run
echo "done linting root directory"
echo "linting with js/wasm.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY}  -e GOOS=js -e GOARCH=wasm -v $(pwd):/opt/workspace -w /opt/workspace ${GOLANGCI_LINT_IMAGE} golangci-lint run
echo "done linting with js/wasm"
echo "linting cmd/aries-agent-rest.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/cmd/aries-agent-rest ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting cmd/aries-agent-rest"
echo "linting cmd/aries-agent-mobile.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/cmd/aries-agent-mobile ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting cmd/aries-agent-mobile"
echo "linting test/bdd.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/test/bdd ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting test/bdd"
echo "linting spi.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/spi ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../.golangci.yml
echo "done linting spi"
echo "linting component/storageutil.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/component/storageutil ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting component/storageutil"
echo "linting component/storage/edv.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/component/storage/edv ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../../.golangci.yml
echo "done linting component/storage/edv"
echo "linting component/storage/leveldb.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/component/storage/leveldb ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../../.golangci.yml
echo "done linting component/storage/leveldb"
echo "linting component/storage/indexeddb.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -e GOOS=js -e GOARCH=wasm -v $(pwd):/opt/workspace -w /opt/workspace/component/storage/indexeddb ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../../.golangci.yml
echo "done linting component/storage/indexeddb"
echo "linting component/storage.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/test/component/storage/ ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../../.golangci.yml
echo "done linting component/storage"

echo "Done Running $0"
