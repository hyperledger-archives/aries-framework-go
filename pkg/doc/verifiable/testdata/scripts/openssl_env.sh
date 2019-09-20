#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

OPENSSL_CMD=${OPENSSL_CMD:-openssl}

if [ ! $(command -v ${OPENSSL_CMD}) ]; then
	docker run -i --rm \
		-v $(pwd):/opt/workspace \
		--workdir /opt/workspace \
		--entrypoint "$1" \
		frapsoft/openssl
    exit 0
fi

$1