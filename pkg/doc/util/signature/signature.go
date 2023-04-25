/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

import (
	"crypto/ed25519"
	"crypto/elliptic"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/models/signature/util"
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
)

// Signer defines generic signer.
type Signer = util.Signer

// NewCryptoSigner creates a new signer based on crypto if possible.
func NewCryptoSigner(crypto cryptoapi.Crypto, kms kmsapi.KeyManager, keyType kmsapi.KeyType) (Signer, error) {
	return util.NewCryptoSigner(crypto, kms, keyType)
}

// NewSigner creates a new signer.
func NewSigner(keyType kmsapi.KeyType) (Signer, error) {
	return util.NewSigner(keyType)
}

// GetSigner returns a new Signer based on privateKey.
// For case ed25519.PrivateKey pubKey is nil.
func GetSigner(privateKeyJWK *jwk.JWK) (Signer, error) {
	return util.GetSigner(privateKeyJWK)
}

// GetEd25519Signer returns Ed25519 Signer with predefined private and public keys.
func GetEd25519Signer(privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) Signer {
	return util.GetEd25519Signer(privKey, pubKey)
}

// MapECCurveToKeyType makes a mapping of Elliptic Curve to KeyType of kms.
func MapECCurveToKeyType(curve elliptic.Curve) (kmsapi.KeyType, error) {
	return util.MapECCurveToKeyType(curve)
}
