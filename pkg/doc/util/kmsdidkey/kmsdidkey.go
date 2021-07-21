/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kmsdidkey

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"

	commonpb "github.com/google/tink/go/proto/common_go_proto"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	didfingerprint "github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint/didfp"
)

// keyTypeCodecs maps kms.KeyType to did:key codec.
// nolint: gochecknoglobals
var keyTypeCodecs = map[kms.KeyType]uint64{
	// signing keys
	kms.ED25519Type:            fingerprint.ED25519PubKeyMultiCodec,
	kms.BLS12381G2Type:         fingerprint.BLS12381g2PubKeyMultiCodec,
	kms.ECDSAP256TypeIEEEP1363: fingerprint.P256PubKeyMultiCodec,
	kms.ECDSAP256TypeDER:       fingerprint.P256PubKeyMultiCodec,
	kms.ECDSAP384TypeIEEEP1363: fingerprint.P384PubKeyMultiCodec,
	kms.ECDSAP384TypeDER:       fingerprint.P384PubKeyMultiCodec,
	kms.ECDSAP521TypeIEEEP1363: fingerprint.P521PubKeyMultiCodec,
	kms.ECDSAP521TypeDER:       fingerprint.P521PubKeyMultiCodec,

	// encryption keys
	kms.X25519ECDHKWType:   fingerprint.X25519PubKeyMultiCodec,
	kms.NISTP256ECDHKWType: fingerprint.P256PubKeyMultiCodec,
	kms.NISTP384ECDHKWType: fingerprint.P384PubKeyMultiCodec,
	kms.NISTP521ECDHKWType: fingerprint.P521PubKeyMultiCodec,
}

// BuildDIDKeyByKeyType creates a did key for pubKeyBytes based on the kms keyType. It parses pubKeyBytes to get
// the key bytes for did key creations.
func BuildDIDKeyByKeyType(pubKeyBytes []byte, keyType kms.KeyType) (string, error) {
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

// EncryptionPubKeyFromDIDKey parses the did:key DID and returns the key's raw value.
// note: for NIST P ECDSA keys, the raw value does not have the compression point.
//	In order to use elliptic.Unmarshal() with the raw value, the uncompressed point ([]byte{4}) must be prepended.
//	see https://github.com/golang/go/blob/master/src/crypto/elliptic/elliptic.go#L384.
//nolint:funlen,gocyclo
func EncryptionPubKeyFromDIDKey(didKey string) (*cryptoapi.PublicKey, error) {
	pubKey, code, err := extractRawKey(didKey)
	if err != nil {
		return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: %w", err)
	}

	var (
		crv   string
		kmtKT kms.KeyType
		kt    string
		x     []byte
		y     []byte
	)

	switch code {
	case fingerprint.ED25519PubKeyMultiCodec: // TODO remove this case when legacyPacker is decommissioned.
		var edKID string

		kmtKT = kms.ED25519Type
		pubEDKey := &cryptoapi.PublicKey{
			X:     pubKey,
			Curve: "Ed25519",
			Type:  "OKP",
		}

		edKID, err = jwkkid.CreateKID(pubKey, kmtKT)
		if err != nil {
			return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: %w", err)
		}

		pubEDKey.KID = edKID

		return pubEDKey, nil
	case fingerprint.X25519PubKeyMultiCodec:
		var (
			mPubXKey []byte
			xKID     string
		)

		kmtKT = kms.X25519ECDHKWType
		pubXKey := &cryptoapi.PublicKey{
			X:     pubKey,
			Curve: "X25519",
			Type:  "OKP",
		}

		mPubXKey, err = json.Marshal(pubXKey)
		if err != nil {
			return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: %w", err)
		}

		xKID, err = jwkkid.CreateKID(mPubXKey, kmtKT)
		if err != nil {
			return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: %w", err)
		}

		pubXKey.KID = xKID

		return pubXKey, nil
	case fingerprint.P256PubKeyMultiCodec:
		ecCRV := elliptic.P256()
		xBig, yBig := elliptic.Unmarshal(ecCRV, pubKey)
		kmtKT = kms.ECDSAP256IEEEP1363
		crv = commonpb.EllipticCurveType_NIST_P256.String()
		kt = "EC"
		x = xBig.Bytes()
		y = yBig.Bytes()
	case fingerprint.P384PubKeyMultiCodec:
		ecCRV := elliptic.P384()
		xBig, yBig := elliptic.Unmarshal(ecCRV, pubKey)
		kmtKT = kms.ECDSAP384IEEEP1363
		crv = commonpb.EllipticCurveType_NIST_P384.String()
		kt = "EC"
		x = xBig.Bytes()
		y = yBig.Bytes()
	case fingerprint.P521PubKeyMultiCodec:
		ecCRV := elliptic.P521()
		xBig, yBig := elliptic.Unmarshal(ecCRV, pubKey)
		kmtKT = kms.ECDSAP521TypeIEEEP1363
		crv = commonpb.EllipticCurveType_NIST_P521.String()
		kt = "EC"
		x = xBig.Bytes()
		y = yBig.Bytes()
	default:
		return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: unsupported key multicodec code [0x%x]", code)
	}

	kid, err := jwkkid.CreateKID(pubKey, kmtKT)
	if err != nil {
		return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: %w", err)
	}

	return &cryptoapi.PublicKey{
		KID:   kid,
		X:     x,
		Y:     y,
		Curve: crv,
		Type:  kt,
	}, nil
}

func extractRawKey(didKey string) ([]byte, uint64, error) {
	idMethodSpecificID, err := didfingerprint.MethodIDFromDIDKey(didKey)
	if err != nil {
		return nil, 0, fmt.Errorf("extractRawKey: MethodIDFromDIDKey failure: %w", err)
	}

	pubKey, code, err := fingerprint.PubKeyFromFingerprint(idMethodSpecificID)
	if err != nil {
		return nil, 0, fmt.Errorf("extractRawKey: PubKeyFromFingerprint failure: %w", err)
	}

	return pubKey, code, nil
}
