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
//      "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
//  )
//
//  func main() {
//      // create recipient side keyset handle
//      recKH, err := keyset.NewHandle(ecdh1pu.ECDH1PU256KWAES256GCMKeyTemplate())
//      if err != nil {
//          //handle error
//      }
//
//      // retrieve recipient public keyset handle
//      recPubKH, err := recKH.Public()
//      if err != nil {
//          //handle error
//      }
//
//      // extract the recipient public key (to be used by the sender later)
//      recECPubKey, err := keyio.ExtractPrimaryPublicKey(kh)
//		// handle error...
//
//      // now create sender keyset handle
//      sKH, err := keyset.NewHandle(ecdh1pu.ECDH1PU256KWAES256GCMKeyTemplate())
//      // handle error...
//
//      // add recipient public key to the sender key handle (assuming the recipient have shared it with the sender)
//      sKH, err = ecdh1pu.AddRecipientsKeys(sKH, []*composite.PublicKey{recECPubKey})
//
//      // for more recipient keys pass in a list: []*composite.PublicKey{recECPubKey1, recECPubKey2, etc.})
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
//      refRecKH , err := keyset.NewHandle( .....reference/rebuild `recKH` here...)
//
//      // extract/retrieve the sender public key reference, usually the sender would do this as follows:
//      senderPubKey, err := keyio.ExtractPrimaryPublicKey(sKH)
//      // handle error...
//
//      // at the recipient side, assuming we have the sender public key above, add it to the recipient handle:
//      refRecKH, err = ecdh1pu.AddSenderKey(refRecKH, senderPubKey)
//
//      // now with the recipient key handle updated with the sender public key, create the decrypter:
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
