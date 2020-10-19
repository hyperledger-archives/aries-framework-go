#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

DEMO_COMPOSE_OP="${DEMO_COMPOSE_OP:-up --force-recreate -d}"
COMPOSE_FILES="${DEMO_COMPOSE_FILES}"
DEMO_PATH="$PWD/${DEMO_COMPOSE_PATH}"
AGENT_PATH="${AGENT_REST_COMPOSE_PATH}"
AGENT_COMPOSE_FILE="$PWD/$AGENT_PATH"
SIDETREE_PATH="${SIDETREE_COMPOSE_PATH}"
SIDETREE_COMPOSE_FILE="$PWD/$SIDETREE_PATH"

set -o allexport
[[ -f $DEMO_PATH/.env ]] && source $DEMO_PATH/.env
set +o allexport

set -o allexport
[[ -f $AGENT_PATH/.env ]] && source $AGENT_PATH/.env
set +o allexport

set -o allexport
[[ -f $SIDETREE_PATH/.env ]] && source $SIDETREE_PATH/.env
set +o allexport

cd $AGENT_COMPOSE_FILE
docker-compose -f docker-compose.yml  ${DEMO_COMPOSE_OP}
cd $SIDETREE_COMPOSE_FILE
docker-compose -f docker-compose.yml ${DEMO_COMPOSE_OP}
cd $DEMO_PATH
docker-compose -f docker-compose.yml ${DEMO_COMPOSE_OP}
