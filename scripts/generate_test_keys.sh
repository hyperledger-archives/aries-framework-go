#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Generating aries-framework-go Test PKI"
mkdir -p test/fixtures/keys/tls

#create CA for TLS creds
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/keys/tls/ec-cakey.pem
openssl req -new -x509 -key test/fixtures/keys/tls/ec-cakey.pem -subj "/C=CA/ST=ON/O=Example Internet CA TLS Inc.:CA Sec/OU=CA Sec" -out test/fixtures/keys/tls/ec-cacert.pem

#create TLS creds
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/keys/tls/ec-key.pem
openssl req -new -key test/fixtures/keys/tls/ec-key.pem -subj "/C=CA/ST=ON/O=Example Inc.:aries-framework-go/OU=aries-framework-go/CN=*.example.com" -reqexts SAN -config ./test/fixtures/openssl/openssl.cnf -out test/fixtures/keys/tls/ec-key.csr
openssl x509 -req -in test/fixtures/keys/tls/ec-key.csr -extensions SAN -extfile ./test/fixtures/openssl/openssl.cnf -CA test/fixtures/keys/tls/ec-cacert.pem -CAkey test/fixtures/keys/tls/ec-cakey.pem -CAcreateserial -out test/fixtures/keys/tls/ec-pubCert.pem -days 365

#create CA for other creds
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/keys/ec-cakey.pem
openssl req -new -x509 -key test/fixtures/keys/ec-cakey.pem -subj "/C=CA/ST=ON/O=Example Internet CA Inc.:CA Sec/OU=CA Sec" -out test/fixtures/keys/ec-cacert.pem

#create creds 1
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/keys/ec-key1.pem
openssl req -new -key test/fixtures/keys/ec-key1.pem -subj "/C=CA/ST=ON/O=Example Inc.:aries-framework-go/OU=aries-framework-go/CN=*.example.com" -reqexts SAN -config ./test/fixtures/openssl/openssl.cnf -out test/fixtures/keys/ec-key1.csr
openssl x509 -req -in test/fixtures/keys/ec-key1.csr -extensions SAN -extfile ./test/fixtures/openssl/openssl.cnf -CA test/fixtures/keys/ec-cacert.pem -CAkey test/fixtures/keys/ec-cakey.pem -CAcreateserial -out test/fixtures/keys/ec-pubCert1.pem -days 365

#extract pubkey 1
openssl x509 -inform pem -in test/fixtures/keys/ec-pubCert1.pem -pubkey -noout > test/fixtures/keys/ec-pubKey1.pem

#create creds 2
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/keys/ec-key2.pem
openssl req -new -key test/fixtures/keys/ec-key2.pem -subj "/C=CA/ST=ON/O=Example Inc.:aries-framework-go/OU=aries-framework-go/CN=*.example.com" -reqexts SAN -config ./test/fixtures/openssl/openssl.cnf -out test/fixtures/keys/ec-key2.csr
openssl x509 -req -in test/fixtures/keys/ec-key2.csr -extensions SAN -extfile ./test/fixtures/openssl/openssl.cnf -CA test/fixtures/keys/ec-cacert.pem -CAkey test/fixtures/keys/ec-cakey.pem -CAcreateserial -out test/fixtures/keys/ec-pubCert2.pem -days 365

#extract pubkey 2
openssl x509 -inform pem -in test/fixtures/keys/ec-pubCert2.pem -pubkey -noout > test/fixtures/keys/ec-pubKey2.pem

#create creds 3
openssl ecparam -name prime256v1 -genkey -noout -out test/fixtures/keys/ec-key3.pem
openssl req -new -key test/fixtures/keys/ec-key3.pem -subj "/C=CA/ST=ON/O=Example Inc.:aries-framework-go/OU=aries-framework-go/CN=*.example.com" -reqexts SAN -config ./test/fixtures/openssl/openssl.cnf -out test/fixtures/keys/ec-key3.csr
openssl x509 -req -in test/fixtures/keys/ec-key3.csr -extensions SAN -extfile ./test/fixtures/openssl/openssl.cnf -CA test/fixtures/keys/ec-cacert.pem -CAkey test/fixtures/keys/ec-cakey.pem -CAcreateserial -out test/fixtures/keys/ec-pubCert3.pem -days 365

#extract pubkey 3
openssl x509 -inform pem -in test/fixtures/keys/ec-pubCert3.pem -pubkey -noout > test/fixtures/keys/ec-pubKey3.pem

echo "done generating aries-framework-go PKI"