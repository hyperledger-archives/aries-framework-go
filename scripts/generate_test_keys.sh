#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e


echo -e  "[SAN]\nsubjectAltName=DNS:*.example.com,DNS:localhost" >> /etc/ssl/openssl.cnf

echo "Generating Aries-Framework-Go Test PKI"
cd /opt/go/src/github.com/hyperledger/aries-framework-go
mkdir -p test/bdd/fixtures/keys/tls

#create CA
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/tls/ec-cakey.pem
openssl req -new -x509 -key test/bdd/fixtures/keys/tls/ec-cakey.pem -subj "/C=CA/ST=ON/O=Example Internet CA Inc.:CA Sec/OU=CA Sec" -out test/bdd/fixtures/keys/tls/ec-cacert.pem

#create TLS creds
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/tls/ec-key.pem
openssl req -new -key test/bdd/fixtures/keys/tls/ec-key.pem -subj "/C=CA/ST=ON/O=Example Inc.:Aries-Framework-Go/OU=Aries-Framework-Go/CN=*.example.com" -reqexts SAN -out test/bdd/fixtures/keys/tls/ec-key.csr
openssl x509 -req -in test/bdd/fixtures/keys/tls/ec-key.csr -extensions SAN -CA test/bdd/fixtures/keys/tls/ec-cacert.pem -CAkey test/bdd/fixtures/keys/tls/ec-cakey.pem -CAcreateserial -out test/bdd/fixtures/keys/tls/ec-pubCert.pem -days 365


echo "done generating Aries-Framework-Go PKI"
