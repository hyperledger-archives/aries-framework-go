/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"hash"

	bbs "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

// PublicKey defines BLS Public Key.
type PublicKey = bbs.PublicKey

// PrivateKey defines BLS Public Key.
type PrivateKey = bbs.PrivateKey

// PublicKeyWithGenerators extends PublicKey with a blinding generator h0, a commitment to the secret key w,
// and a generator for each message h.
type PublicKeyWithGenerators = bbs.PublicKeyWithGenerators

// UnmarshalPrivateKey unmarshals PrivateKey.
func UnmarshalPrivateKey(privKeyBytes []byte) (*PrivateKey, error) {
	return bbs.UnmarshalPrivateKey(privKeyBytes)
}

// UnmarshalPublicKey parses a PublicKey from bytes.
func UnmarshalPublicKey(pubKeyBytes []byte) (*PublicKey, error) {
	return bbs.UnmarshalPublicKey(pubKeyBytes)
}

// GenerateKeyPair generates BBS+ PublicKey and PrivateKey pair.
func GenerateKeyPair(h func() hash.Hash, seed []byte) (*PublicKey, *PrivateKey, error) {
	return bbs.GenerateKeyPair(h, seed)
}
