#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

DEMO_COMPOSE_OP="${DEMO_COMPOSE_OP:-up --force-recreate}"
COMPOSE_FILES="${DEMO_COMPOSE_FILES}"
DEMO_PATH="${DEMO_COMPOSE_PATH}"
AGENT_PATH="${AGENT_COMPOSE_PATH}"
AGENT_COMPOSE_FILE="$PWD/$AGENT_PATH/docker-compose.yml"
SIDETREE_PATH="${SIDETREE_COMPOSE_PATH}"
SIDETREE_COMPOSE_FILE="$PWD/$SIDETREE_PATH/docker-compose.yml"

set -o allexport
[[ -f $DEMO_PATH/.env ]] && source $DEMO_PATH/.env
set +o allexport

set -o allexport
[[ -f $AGENT_PATH/.env ]] && source $AGENT_PATH/.env
set +o allexport

set -o allexport
[[ -f $SIDETREE_PATH/.env ]] && source $SIDETREE_PATH/.env
set +o allexport

cd $DEMO_PATH
echo docker-compose -f docker-compose-demo.yml -f ${AGENT_COMPOSE_FILE} -f ${SIDETREE_COMPOSE_FILE} ${DEMO_COMPOSE_OP}
docker-compose -f docker-compose-demo.yml -f ${AGENT_COMPOSE_FILE} -f ${SIDETREE_COMPOSE_FILE} ${DEMO_COMPOSE_OP}

