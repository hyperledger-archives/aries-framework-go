/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aead_test

import (
	"encoding/base64"
	"fmt"
	"log"
	"testing"

	tinkaead "github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead"
)

func Example() {
	kh, err := keyset.NewHandle(aead.AES128CBCHMACSHA256KeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	a, err := tinkaead.New(kh)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("this message needs to be encrypted")
	aad := []byte("this data needs to be authenticated, but not encrypted")

	ct, err := a.Encrypt(msg, aad)
	if err != nil {
		log.Fatal(err)
	}

	pt, err := a.Decrypt(ct, aad)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Ciphertext: %s\n", base64.StdEncoding.EncodeToString(ct))
	fmt.Printf("Original  plaintext: %s\n", msg)
	fmt.Printf("Decrypted Plaintext: %s\n", pt)
}

func TestAEADInit(t *testing.T) {
	aesCBCHMACAEADTypeURL := "type.hyperledger.org/hyperledger.aries.crypto.tink.AesCbcHmacAeadKey"

	// Check for CBC-HMAC key manager.
	_, err := registry.GetKeyManager(aesCBCHMACAEADTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}
