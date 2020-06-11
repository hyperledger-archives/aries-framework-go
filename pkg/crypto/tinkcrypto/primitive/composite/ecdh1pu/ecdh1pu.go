/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package ecdh1pu provides implementations of payload encryption using ECDH-1PU KW key wrapping with AEAD primitives.
//
// The functionality of ecdh1pu Encryption is represented as a pair of
// primitives (interfaces):
//
//  * ECDH1PUEncrypt for encryption of data and aad for a given list of recipients keys
//
//  * ECDH1PUDecrypt for decryption of data for a certain recipient key and returning decrypted plaintext
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
//      "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
//      "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh1pu"
//  )
//
//  func main() {
//      // create recipient side keyset handle
//      recKH, err := keyset.NewHandle(ecdh1pu.ECDH1PU256KWAES256GCMKeyTemplate())
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
//      pubKeyWriter := ecdh1pu.NewWriter(buf)
//      err = recPubKH.WriteWithNoSecrets(pubKeyWriter)
//      if err != nil {
//          //handle error
//      }
//
//      ecPubKey := new(composite.PublicKey)
//      err := json.Unmarshal(buf.Bytes(), ecPubKey)
//
//      // now create sender keyset handle with recipient public key (ecPubKey)
//      sKH, err := keyset.NewHandle(ecdh1pu.ECDH1PU256KWAES256GCMKeyTemplateWithRecipients(
//     		[]composite.PublicKey{*ecPubKey}))
//      if err != nil {
//          // handle error
//      }
//
//      // for more recipient keys pass in a list: []composite.PublicKey{*ecPubKey1, *ecPubKey2, *ecPubKey3, etc.})
//      // at least 1 recipient is required.
//
//      // extract sender public keyset handle to encrypt
//      senderPubKH, err := sKH.Public()
//      if err != nil {
//          //handle error
//      }
//
//      e := ecdh1pu.NewECDH1PUEncrypt(senderPubKH)
//
//      ct, err = e.Encrypt([]byte("secret message"), []byte("some aad"))
//      if err != nil {
//          // handle error
//      }
//
//      // get a handle on the decryption key material for a recipient
//      // this is usually reloading the recipient's keyset handle (ie: `recKH` above) from a kms
//      refRecKH , err := keyset.NewHandle( .....reference/rebuild `recKH` here...);
//      d := ecdh1pu.NewECDH1PUDecrypt(refRecKH)
//
//      pt, err := d.Decrypt(ct)
//      if err != nil {
//          // handle error
//      }
//  }
package ecdh1pu

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
)

// TODO - find a better way to setup tink than init.
// nolint: gochecknoinits
func init() {
	// TODO - avoid the tink registry singleton (if possible).
	err := registry.RegisterKeyManager(newECDH1PUPrivateKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdh1pu.init() failed: %v", err))
	}

	err = registry.RegisterKeyManager(newECDH1PUPublicKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdh1pu.init() failed: %v", err))
	}
}
