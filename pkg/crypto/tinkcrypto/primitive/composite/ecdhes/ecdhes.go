/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package ecdhes provides implementations of payload encryption using ECDH-ES KW key wrapping with AEAD primitives.
//
// The functionality of ecdhes Encryption is represented as a pair of
// primitives (interfaces):
//
//  * ECDHESEncrypt for encryption of data and aad for a given list of recipients keys
//
//  * ECDHESDecrypt for decryption of data for a certain recipient key and returning decrypted plaintext
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
//	    ecdhessubtle "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes/subtle"
//      "github.com/aries-framework-go/pkg/crypto/tinkcrypto/composite/ecdhes"
//  )
//
//  func main() {
//      // create recipient side keyset handle
//      recKH, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
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
//      pubKeyWriter := ecdhes.NewWriter(buf)
//      err = recPubKH.WriteWithNoSecrets(pubKeyWriter)
//      if err != nil {
//          //handle error
//      }
//
//      ecPubKey := new(ecdhessubtle.ECPublicKey)
//      err := json.Unmarshal(buf.Bytes(), ecPubKey)
//
//      // now create sender keyset handle with recipient public key (ecPubKey)
//      sKH, err := keyset.NewHandle(ECDHES256KWAES256GCMKeyTemplateWithRecipients(
//     		[]ecdhessubtle.ECPublicKey{*ecPubKey}))
//      if err != nil {
//          // handle error
//      }
//
//      // for more recipient keys pass in a list: []ecdhessubtle.ECPublicKey{*ecPubKey1, *ecPubKey2, *ecPubKey3, etc.})
//      // at least 1 recipient is required.
//
//      // extract sender public keyset handle to encrypt
//      senderPubKH, err := sKH.Public()
//      if err != nil {
//          //handle error
//      }
//
//      e := ecdhes.NewECDHESEncrypt(senderPubKH)
//
//      ct, err = e.Encrypt([]byte("secret message"), []byte("some aad"))
//      if err != nil {
//          // handle error
//      }
//
//      // get a handle on the decryption key material for a recipient
//      // this is usually reloading the recipient's keyset handle (ie: `recKH` above) from a kms
//      refRecKH , err := keyset.NewHandle( .....reference/rebuild `recKH` here...);
//      d := ecdhes.NewECDHESDecrypt(refRecKH)
//
//      pt, err := d.Decrypt(ct)
//      if err != nil {
//          // handle error
//      }
//  }
package ecdhes

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
)

// TODO - find a better way to setup tink than init.
// nolint: gochecknoinits
func init() {
	// TODO - avoid the tink registry singleton.
	err := registry.RegisterKeyManager(newECDHESPrivateKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdhes.init() failed: %v", err))
	}

	err = registry.RegisterKeyManager(newECDHESPublicKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdhes.init() failed: %v", err))
	}
}
