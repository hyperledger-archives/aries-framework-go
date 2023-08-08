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

echo "linting spi.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace/spi ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../.golangci.yml
echo "done linting spi"
echo "linting component/log.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace/component/log ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting component/log"
echo "linting component/storageutil.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace/component/storageutil ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting component/storageutil"
echo "linting component/kmscrypto.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace/component/kmscrypto ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting component/kmscrypto"
echo "linting component/models.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace/component/models ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting component/models"
echo "linting component/vdr.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace/component/vdr ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting component/vdr"
echo "linting component/didconfig.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace/component/didconfig ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting component/didconfig"
echo "linting component/storage/edv.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace/component/storage/edv ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../../.golangci.yml
echo "done linting component/storage/edv"
echo "linting component/storage/leveldb.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace/component/storage/leveldb ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../../.golangci.yml
echo "done linting component/storage/leveldb"
echo "linting component/storage/indexeddb.."
${DOCKER_CMD} run ${SHARED_OPTS} -e GOOS=js -e GOARCH=wasm -w /opt/workspace/component/storage/indexeddb ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../../.golangci.yml
echo "done linting component/storage/indexeddb"
echo "linting component/storage.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace/test/component/storage/ ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../../.golangci.yml
echo "done linting component/storage"

echo "Done Running $0"
