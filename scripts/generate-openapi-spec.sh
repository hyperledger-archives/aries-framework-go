#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

SPEC_LOC="${SPEC_LOC}"
SPEC_DIR="cmd/aries-agent-rest"
WORKING_DIR="/opt"
OUTPUT="$SPEC_LOC/openAPI.yml"
IMAGE="${DOCKER_IMAGE:-quay.io/goswagger/swagger}"
IMAGE_VERSION="${DOCKER_IMAGE_VERSION:-latest}"

# generate and validate commands
GENERATE_COMMAND="generate spec -w $SPEC_DIR -o $OUTPUT"
VALIDATE_COMMAND="validate $OUTPUT"

echo "Generating Open API spec"
docker run --rm -v $(pwd):$WORKING_DIR -w $WORKING_DIR ${IMAGE}:${IMAGE_VERSION} $GENERATE_COMMAND

echo "Validating generated spec"
docker run --rm -v $(pwd):$WORKING_DIR -w $WORKING_DIR ${IMAGE}:${IMAGE_VERSION} $VALIDATE_COMMAND