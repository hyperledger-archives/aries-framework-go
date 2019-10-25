#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

WORK_DIR="${GOPATH}/src/github.com/hyperledger/aries-framework-go"
CMD_PATH="cmd/aries-agentd"
BUILD_PATH="${WORK_DIR}/build/cmd-${ID}"
ARIES_CMD="${BUILD_PATH}/aries-agentd"

echo "Building aries-agentd"
mkdir -p ${BUILD_PATH}
cd ${CMD_PATH}
go build -o ${ARIES_CMD}

echo "Starting aries-agentd"
${ARIES_CMD} start --api-host ${API_HOST} --inbound-host ${INBOUND_HOST} --webhook-url ${WEBHOOK_URL} -d ${DB_LOC}