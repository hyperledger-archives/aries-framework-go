#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Generating aries-framework-go Test PKI"
mkdir -p testdata/crypto/tls

cat > testdata/crypto/openssl.cnf << EOF
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

[ req ]
distinguished_name	= req_distinguished_name

[ req_distinguished_name ]

[SAN]
subjectAltName=DNS:*.example.com,DNS:localhost
EOF

#create CA for TLS creds
openssl ecparam -name prime256v1 -genkey -noout -out testdata/crypto/tls/ec-cakey.pem
openssl req -new -x509 -key testdata/crypto/tls/ec-cakey.pem -subj "/C=CA/ST=ON/O=Example Internet CA TLS Inc.:CA Sec/OU=CA Sec" -out testdata/crypto/tls/ec-cacert.pem

#create TLS creds
openssl ecparam -name prime256v1 -genkey -noout -out testdata/crypto/tls/ec-key.pem
openssl req -new -key testdata/crypto/tls/ec-key.pem -subj "/C=CA/ST=ON/O=Example Inc.:aries-framework-go/OU=aries-framework-go/CN=*.example.com" -reqexts SAN -config testdata/crypto/openssl.cnf -out testdata/crypto/tls/ec-key.csr
openssl x509 -req -in testdata/crypto/tls/ec-key.csr -extensions SAN -extfile testdata/crypto/openssl.cnf -CA testdata/crypto/tls/ec-cacert.pem -CAkey testdata/crypto/tls/ec-cakey.pem -CAcreateserial -out testdata/crypto/tls/ec-pubCert.pem -days 365

#create CA for other creds
openssl ecparam -name prime256v1 -genkey -noout -out testdata/crypto/ec-cakey.pem
openssl req -new -x509 -key testdata/crypto/ec-cakey.pem -subj "/C=CA/ST=ON/O=Example Internet CA Inc.:CA Sec/OU=CA Sec" -out testdata/crypto/ec-cacert.pem

#create creds 1
openssl ecparam -name prime256v1 -genkey -noout -out testdata/crypto/ec-key1.pem
openssl req -new -key testdata/crypto/ec-key1.pem -subj "/C=CA/ST=ON/O=Example Inc.:aries-framework-go/OU=aries-framework-go/CN=*.example.com" -reqexts SAN -config testdata/crypto/openssl.cnf -out testdata/crypto/ec-key1.csr
openssl x509 -req -in testdata/crypto/ec-key1.csr -extensions SAN -extfile testdata/crypto/openssl.cnf -CA testdata/crypto/ec-cacert.pem -CAkey testdata/crypto/ec-cakey.pem -CAcreateserial -out testdata/crypto/ec-pubCert1.pem -days 365

#extract pubkey 1
openssl x509 -inform pem -in testdata/crypto/ec-pubCert1.pem -pubkey -noout > testdata/crypto/ec-pubKey1.pem

#create creds 2
openssl ecparam -name prime256v1 -genkey -noout -out testdata/crypto/ec-key2.pem
openssl req -new -key testdata/crypto/ec-key2.pem -subj "/C=CA/ST=ON/O=Example Inc.:aries-framework-go/OU=aries-framework-go/CN=*.example.com" -reqexts SAN -config testdata/crypto/openssl.cnf -out testdata/crypto/ec-key2.csr
openssl x509 -req -in testdata/crypto/ec-key2.csr -extensions SAN -extfile testdata/crypto/openssl.cnf -CA testdata/crypto/ec-cacert.pem -CAkey testdata/crypto/ec-cakey.pem -CAcreateserial -out testdata/crypto/ec-pubCert2.pem -days 365

#extract pubkey 2
openssl x509 -inform pem -in testdata/crypto/ec-pubCert2.pem -pubkey -noout > testdata/crypto/ec-pubKey2.pem

#create creds 3
openssl ecparam -name prime256v1 -genkey -noout -out testdata/crypto/ec-key3.pem
openssl req -new -key testdata/crypto/ec-key3.pem -subj "/C=CA/ST=ON/O=Example Inc.:aries-framework-go/OU=aries-framework-go/CN=*.example.com" -reqexts SAN -config testdata/crypto/openssl.cnf -out testdata/crypto/ec-key3.csr
openssl x509 -req -in testdata/crypto/ec-key3.csr -extensions SAN -extfile testdata/crypto/openssl.cnf -CA testdata/crypto/ec-cacert.pem -CAkey testdata/crypto/ec-cakey.pem -CAcreateserial -out testdata/crypto/ec-pubCert3.pem -days 365

#extract pubkey 3
openssl x509 -inform pem -in testdata/crypto/ec-pubCert3.pem -pubkey -noout > testdata/crypto/ec-pubKey3.pem

rm -f testdata/crypto/openssl.cnf
echo "done generating aries-framework-go PKI"