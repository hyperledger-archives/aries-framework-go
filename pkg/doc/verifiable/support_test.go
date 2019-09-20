/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
)

func readPublicKey(keyFilePath string) (*rsa.PublicKey, error) {
	pub, err := ioutil.ReadFile(filepath.Clean(keyFilePath))
	if err != nil {
		return nil, fmt.Errorf("failed to read pem file: %s", keyFilePath)
	}

	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		return nil, errors.New("failed to decode PEM file")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	var pubKey *rsa.PublicKey
	var ok bool
	if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, errors.New("unexpected type of public key")
	}
	return pubKey, nil
}

func readPrivateKey(keyFilePath string) (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(filepath.Clean(keyFilePath))
	if err != nil {
		return nil, fmt.Errorf("failed to read pem file: %s", keyFilePath)
	}

	privPem, _ := pem.Decode(priv)
	if privPem == nil {
		return nil, errors.New("failed to decode PEM file")
	}

	var privKey *rsa.PrivateKey
	if privKey, err = x509.ParsePKCS1PrivateKey(privPem.Bytes); err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privKey, nil
}
