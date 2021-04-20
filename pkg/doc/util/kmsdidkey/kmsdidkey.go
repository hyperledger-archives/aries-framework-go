/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kmsdidkey

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

// keyTypeCodecs maps kms.KeyType to did:key codec.
// nolint: gochecknoglobals
var keyTypeCodecs = map[kms.KeyType]uint64{
	// signing keys
	kms.ED25519:                fingerprint.ED25519PubKeyMultiCodec,
	kms.BLS12381G2Type:         fingerprint.BLS12381g2PubKeyMultiCodec,
	kms.ECDSAP256TypeIEEEP1363: fingerprint.P256PubKeyMultiCodec,
	kms.ECDSAP256TypeDER:       fingerprint.P256PubKeyMultiCodec,
	kms.ECDSAP384TypeIEEEP1363: fingerprint.P384PubKeyMultiCodec,
	kms.ECDSAP384TypeDER:       fingerprint.P384PubKeyMultiCodec,
	kms.ECDSAP521TypeIEEEP1363: fingerprint.P521PubKeyMultiCodec,
	kms.ECDSAP521TypeDER:       fingerprint.P521PubKeyMultiCodec,

	// encryption keys
	kms.X25519ECDHKWType:   fingerprint.X25519PubKeyMultiCodec,
	kms.NISTP256ECDHKW:     fingerprint.P256PubKeyMultiCodec,
	kms.NISTP384ECDHKWType: fingerprint.P384PubKeyMultiCodec,
	kms.NISTP521ECDHKWType: fingerprint.P521PubKeyMultiCodec,
}

// BuildDIDKeyByKMSKeyType creates a did key for pubKeyBytes based on the kms keyType.
func BuildDIDKeyByKMSKeyType(pubKeyBytes []byte, keyType kms.KeyType) (string, error) {
	switch keyType {
	case kms.X25519ECDHKW:
		pubKey := &cryptoapi.PublicKey{}

		err := json.Unmarshal(pubKeyBytes, pubKey)
		if err != nil {
			return "", fmt.Errorf("buildDIDkeyByKMSKeyType failed to unmarshal key type %v: %w", keyType, err)
		}

		pubKeyBytes = make([]byte, len(pubKey.X))
		copy(pubKeyBytes, pubKey.X)
	case kms.NISTP256ECDHKWType, kms.NISTP384ECDHKWType, kms.NISTP521ECDHKWType:
		pubKey := &cryptoapi.PublicKey{}

		err := json.Unmarshal(pubKeyBytes, pubKey)
		if err != nil {
			return "", fmt.Errorf("buildDIDkeyByKMSKeyType failed to unmarshal key type %v: %w", keyType, err)
		}

		ecKey, err := cryptoapi.ToECKey(pubKey)
		if err != nil {
			return "", fmt.Errorf("buildDIDkeyByKMSKeyType failed to unmarshal key type %v: %w", keyType, err)
		}

		pubKeyBytes = elliptic.Marshal(ecKey.Curve, ecKey.X, ecKey.Y)
	}

	if codec, ok := keyTypeCodecs[keyType]; ok {
		kid, _ := fingerprint.CreateDIDKeyByCode(codec, pubKeyBytes)

		return kid, nil
	}

	return "", fmt.Errorf("keyType '%s' does not have a multi-base codec", keyType)
}
