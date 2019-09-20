#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Generating aries-framework-go test keys for Verifiable Credential"

mkdir -p testdata/crypto

# Generate Issuer keys.
openssl genrsa -out testdata/crypto/issuer_private.pem 2048
openssl rsa -in testdata/crypto/issuer_private.pem -outform PEM -pubout -out testdata/crypto/issuer_public.pem

# Generate Holder keys.
openssl genrsa -out testdata/crypto/holder_private.pem 2048
openssl rsa -in testdata/crypto/holder_private.pem -outform PEM -pubout -out testdata/crypto/holder_public.pem
