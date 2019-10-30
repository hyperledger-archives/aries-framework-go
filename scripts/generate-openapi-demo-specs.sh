#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

BASE_SPEC_LOC="${SPEC_PATH}/openAPI.yml"
DEMO_PATH="${OPENAPI_DEMO_PATH}"
IMAGE="${DOCKER_IMAGE:-quay.io/goswagger/swagger}"
IMAGE_VERSION="${DOCKER_IMAGE_VERSION:-latest}"
OUTPUT_PATH="$DEMO_PATH/specs"

if [ ! -f "$BASE_SPEC_LOC" ]; then
    echo "'$BASE_SPEC_LOC' doesn't exists"
    exit 1
fi

set -o allexport
[[ -f $DEMO_PATH/.env ]] && source $DEMO_PATH/.env
set +o allexport

mkdir -p $OUTPUT_PATH

# generate sub specs using .env entries and mix them using 'swagger mixin'
while IFS='=' read -r name value ; do
  if [[ $name == *'_API_HOST' ]]; then
    result="${!name}"
    echo "host: $result" > $OUTPUT_PATH/$result.yml
    command="mixin $BASE_SPEC_LOC $OUTPUT_PATH/${result}.yml -o $OUTPUT_PATH/openapi-${result}.yml --format yaml"
    docker run --rm -e GOPATH=$HOME/go:/go -v $HOME:$HOME -w $(pwd) ${IMAGE}:${IMAGE_VERSION} $command
    rm -rf $OUTPUT_PATH/$result.yml
  fi
done < <(env)


