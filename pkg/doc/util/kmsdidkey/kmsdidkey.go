/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kmsdidkey

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/kmsdidkey"
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

// BuildDIDKeyByKeyType creates a did key for pubKeyBytes based on the kms keyType.
func BuildDIDKeyByKeyType(pubKeyBytes []byte, keyType kms.KeyType) (string, error) {
	return kmsdidkey.BuildDIDKeyByKeyType(pubKeyBytes, keyType)
}

// EncryptionPubKeyFromDIDKey parses the did:key DID and returns the key's raw value.
// note: for NIST P ECDSA keys, the raw value does not have the compression point.
//
//	In order to use elliptic.Unmarshal() with the raw value, the uncompressed point ([]byte{4}) must be prepended.
//	see https://github.com/golang/go/blob/master/src/crypto/elliptic/elliptic.go#L384.
//
//nolint:funlen,gocyclo
func EncryptionPubKeyFromDIDKey(didKey string) (*cryptoapi.PublicKey, error) {
	return kmsdidkey.EncryptionPubKeyFromDIDKey(didKey)
}

// GetBase58PubKeyFromDIDKey parses the did:key DID and returns the key's base58 encoded value.
func GetBase58PubKeyFromDIDKey(didKey string) (string, error) {
	return kmsdidkey.GetBase58PubKeyFromDIDKey(didKey)
}
