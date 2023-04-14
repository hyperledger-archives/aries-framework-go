/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package ecdh provides implementations of payload encryption using ECDH-ES/1PU KW key wrapping with AEAD primitives.
//
// The functionality of ecdh Encryption is represented as a pair of
// primitives (interfaces):
//
//  * ECDHEncrypt for encryption of data and aad for a given cek (recipients cek wrapping is not done in this primitive)
//
//  * ECDHDecrypt for decryption of data for a given cek and returning decrypted plaintext
//
//
// Example:
//
//  package main
//
//  import (
//      "bytes"
//
//      "github.com/google/tink/go/keyset"
//
//      "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
//      "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
//  )
//
//  func main() {
//      // create recipient side keyset handle
//      recKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
//      if err != nil {
//          //handle error
//      }
//
//      // extract recipient public keyset handle and key
//      recPubKH, err := recKH.Public()
//      if err != nil {
//          //handle error
//      }
//
//      buf := new(bytes.Buffer)
//      pubKeyWriter := ecdh.NewWriter(buf)
//      err = recPubKH.WriteWithNoSecrets(pubKeyWriter)
//      if err != nil {
//          //handle error
//      }
//      // ecPubKey represents a recipient public key that can be used to wrap cek
//      ecPubKey := new(composite.VerificationMethod)
//      err := json.Unmarshal(buf.Bytes(), ecPubKey)
//
//		// see pkg/crypto/tinkcrypto to see how you can wrap a shared secret (cek)
//
//		// once a cek is created create an ECDH KH that can be used to encrypt plaintext as follows
//		// for AES256GCM content encryption using a NIST P key for cek wrapping as an example
//		kt := ecdh.KeyTemplateForECDHPrimitiveWithCEK(cek, true, ecdh.AES256GCM)
//
//		kh, err := keyset.NewHandle(kt)
//		if err != nil {
//			// handle error
//		}
//
//		pubKH, err := kh.Public()
//		if err != nil {
//			// handle error
//		}
//
//		// finally get the encryption primitive from the public key handle created above
//		e:= ecdh.NewECDHEncrypt(pubKH)
//
//		// and now encrypt using e
//      ct, err = e.Encrypt([]byte("secret message"), []byte("some aad"))
//      if err != nil {
//          // handle error
//      }
//
//      // to decrypt, recreate kh for the cek (once unwrapped from pkg/crypto)
//		// for AES256GCM content encryption using a NIST P key for cek wrapping to match the encryption template above
//		kt = ecdh.KeyTemplateForECDHPrimitiveWithCEK(cek, true, ecdh.AES256GCM)
//
//		kh, err = keyset.NewHandle(kt)
//		if err != nil {
//			// handle error
//		}
//
//		// get the decryption primtive for kh
//      d := ecdh.NewECDHDecrypt(kh)
//
//		// and decrypt
//      pt, err := d.Decrypt(ct)
//      if err != nil {
//          // handle error
//      }
//  }
package ecdh

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
)

// TODO - find a better way to setup tink than init.
// nolint: gochecknoinits
func init() {
	// TODO - avoid the tink registry singleton.
	err := registry.RegisterKeyManager(newECDHNISTPAESPrivateKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdh.init() failed: %v", err))
	}

	err = registry.RegisterKeyManager(newECDHNISTPAESPublicKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdh.init() failed: %v", err))
	}

	err = registry.RegisterKeyManager(newX25519ECDHKWPrivateKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdh.init() failed: %v", err))
	}

	err = registry.RegisterKeyManager(newX25519ECDHKWPublicKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdh.init() failed: %v", err))
	}
}
