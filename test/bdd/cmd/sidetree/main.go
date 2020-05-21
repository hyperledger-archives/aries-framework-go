/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/sidetree"
)

func main() {
	key, err := base64.RawURLEncoding.DecodeString(os.Args[3])
	if err != nil {
		panic(err)
	}

	jwk, err := jose.JWKFromPublicKey(ed25519.PublicKey(key))
	if err != nil {
		panic(err)
	}

	doc, err := sidetree.CreateDID(&sidetree.CreateDIDParams{
		URL:             os.Args[1],
		KeyID:           os.Args[2],
		JWK:             jwk,
		ServiceEndpoint: os.Args[4],
	})
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(doc.ID)
}
