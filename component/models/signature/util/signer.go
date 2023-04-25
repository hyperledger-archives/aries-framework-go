/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"

	"github.com/hyperledger/aries-framework-go/component/models/signature/util/internal/signer"
)

// NewCryptoSigner creates a new signer based on crypto if possible.
func NewCryptoSigner(crypto cryptoapi.Crypto, kms kmsapi.KeyManager, keyType kmsapi.KeyType) (Signer, error) {
	switch keyType {
	case kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP256TypeIEEEP1363,
		kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP384TypeIEEEP1363,
		kmsapi.ECDSAP521TypeDER, kmsapi.ECDSAP521TypeIEEEP1363,
		kmsapi.ED25519Type:
		return signer.NewCryptoSigner(crypto, kms, keyType)

	case kmsapi.ECDSASecp256k1DER, kmsapi.ECDSASecp256k1TypeIEEEP1363:
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

// GetSigner returns a new Signer based on privateKey.
// For case ed25519.PrivateKey pubKey is nil.
func GetSigner(privateKeyJWK *jwk.JWK) (Signer, error) {
	switch privateKey := privateKeyJWK.JSONWebKey.Key.(type) {
	case *ecdsa.PrivateKey:
		return signer.GetECDSASigner(privateKey)
	case ed25519.PrivateKey:
		return signer.GetEd25519Signer(privateKey, nil), nil
	case *rsa.PrivateKey:
		return getRsaSigner(privateKeyJWK, privateKey)
	}

	return nil, errors.New("invalid key type")
}

func getRsaSigner(privateKeyJWK *jwk.JWK, rsaPrivateKey *rsa.PrivateKey) (Signer, error) {
	keyType, err := privateKeyJWK.KeyType()
	if err != nil {
		return nil, err
	}

	switch keyType {
	case kmsapi.RSARS256Type:
		return signer.GetRS256Signer(rsaPrivateKey), nil

	case kmsapi.RSAPS256Type:
		return signer.GetPS256Signer(rsaPrivateKey), nil
	}

	return nil, errors.New("invalid key type")
}

// GetEd25519Signer returns Ed25519 Signer with predefined private and public keys.
func GetEd25519Signer(privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) Signer {
	return signer.GetEd25519Signer(privKey, pubKey)
}
