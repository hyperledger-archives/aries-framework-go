#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

SPEC_LOC="${SPEC_LOC}"
SPEC_META="${SPEC_META:-cmd/aries-agent-rest}"
OUTPUT="$PWD/$SPEC_LOC/openAPI.yml"
IMAGE="${DOCKER_IMAGE:-quay.io/goswagger/swagger}"
IMAGE_VERSION="${DOCKER_IMAGE_VERSION:-latest}"

cd $SPEC_META

# generate and validate commands
GENERATE_COMMAND="generate spec main.go -o $OUTPUT"
VALIDATE_COMMAND="validate $OUTPUT"

echo "Generating Open API spec"
docker run --rm -v $HOME:$HOME -w $(pwd) ${IMAGE}:${IMAGE_VERSION} $GENERATE_COMMAND

echo "Validating generated spec"
docker run --rm -v $HOME:$HOME -w $(pwd) ${IMAGE}:${IMAGE_VERSION} $VALIDATE_COMMAND