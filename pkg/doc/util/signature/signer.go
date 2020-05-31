/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

import (
	"crypto/ed25519"
	"errors"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature/internal/signer"
	kmsapi "github.com/hyperledger/aries-framework-go/pkg/kms"
)

// NewCryptoSigner creates a new signer based on crypto if possible.
func NewCryptoSigner(crypto cryptoapi.Crypto, kms kmsapi.KeyManager, keyType kmsapi.KeyType) (Signer, error) {
	switch keyType {
	case kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP256TypeIEEEP1363,
		kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP384TypeIEEEP1363,
		kmsapi.ECDSAP521TypeDER, kmsapi.ECDSAP521TypeIEEEP1363,
		kmsapi.ED25519Type:
		return signer.NewCryptoSigner(crypto, kms, keyType)

	case kmsapi.ECDSASecp256k1TypeIEEEP1363:
		// TODO use crypto signer when available (https://github.com/hyperledger/aries-framework-go/issues/1285)
		return signer.NewECDSASecp256k1Signer()

	case kmsapi.RSARS256Type:
		return signer.NewRS256Signer()

	case kmsapi.RSAPS256Type:
		return signer.NewPS256Signer()

	default:
		return nil, errors.New("unsupported key type")
	}
}

// NewSigner creates a new signer.
func NewSigner(keyType kmsapi.KeyType) (Signer, error) {
	switch keyType {
	case kmsapi.ED25519Type:
		return signer.NewEd25519Signer()

	case kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP256TypeIEEEP1363:
		return signer.NewECDSAP256Signer()

	case kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP384TypeIEEEP1363:
		return signer.NewECDSAP384Signer()

	case kmsapi.ECDSAP521TypeDER, kmsapi.ECDSAP521TypeIEEEP1363:
		return signer.NewECDSAP521Signer()

	case kmsapi.ECDSASecp256k1TypeIEEEP1363:
		return signer.NewECDSASecp256k1Signer()

	case kmsapi.RSARS256Type:
		return signer.NewRS256Signer()

	case kmsapi.RSAPS256Type:
		return signer.NewPS256Signer()

	default:
		return nil, errors.New("unsupported key type")
	}
}

// GetEd25519Signer returns Ed25519 Signer with predefined private and public keys.
func GetEd25519Signer(privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) Signer {
	return signer.GetEd25519Signer(privKey, pubKey)
}
