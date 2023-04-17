/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keyio

import (
	"io"

	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/keyio"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
)

// Package keyio supports exporting of Composite keys (aka Write) and converting the public key part of the a composite
// key (aka PublicKeyToHandle to be used as a valid Tink key)

// PubKeyWriter will write the raw bytes of a Tink KeySet's primary public key. The raw bytes are a marshaled
// composite.VerificationMethod type.
// The keyset must have a keyURL value equal to either one of the public key URLs:
//   - `nistPECDHKWPublicKeyTypeURL`
//   - `x25519ECDHKWPublicKeyTypeURL`
//
// constants of ecdh package.
// Note: This writer should be used only for ECDH public key exports. Other export of public keys should be
//
//	called via localkms package.
type PubKeyWriter = keyio.PubKeyWriter

// NewWriter creates a new PubKeyWriter instance.
func NewWriter(w io.Writer) *PubKeyWriter {
	return keyio.NewWriter(w)
}

// ExtractPrimaryPublicKey is a utility function that will extract the main public key from *keyset.Handle kh.
func ExtractPrimaryPublicKey(kh *keyset.Handle) (*cryptoapi.PublicKey, error) {
	return keyio.ExtractPrimaryPublicKey(kh)
}

// PublicKeyToKeysetHandle converts pubKey into a *keyset.Handle where pubKey could be either a sender or a
// recipient key. The resulting handle cannot be directly used for primitive execution as the cek is not set. This
// function serves as a helper to get a senderKH to be used as an option for ECDH execution (for ECDH-1PU/authcrypt).
// The keyset handle will be set with either AES256-GCM, AES128CBC+SHA256, AES192CBC+SHA384, AES256CBC+SHA384 or
// AES256CBC+SHA512 AEAD key template for content encryption. With:
// - pubKey the public key to convert.
// - aeadAlg the content encryption algorithm to use along the ECDH primitive.
func PublicKeyToKeysetHandle(pubKey *cryptoapi.PublicKey, aeadAlg ecdh.AEADAlg) (*keyset.Handle, error) {
	return keyio.PublicKeyToKeysetHandle(pubKey, aeadAlg)
}

// PrivateKeyToKeysetHandle converts privKey into a *keyset.Handle where privKey could be either a sender or a
// recipient key. The resulting handle cannot be directly used for primitive execution as the cek is not set. This
// function serves as a helper to get a senderKH to be used as an option for ECDH execution (for ECDH-1PU/authcrypt).
// The keyset handle will be set with either AES256-GCM, AES128CBC+SHA256, AES192CBC+SHA384, AES256CBC+SHA384 or
// AES256CBC+SHA512 AEAD key template for content encryption. With:
// - privKey the private key to convert.
// - aeadAlg the content encryption algorithm to use along the ECDH primitive.
func PrivateKeyToKeysetHandle(privKey *cryptoapi.PrivateKey, aeadAlg ecdh.AEADAlg) (*keyset.Handle, error) {
	return keyio.PrivateKeyToKeysetHandle(privKey, aeadAlg)
}
