/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kmsdidkey

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	commonpb "github.com/google/tink/go/proto/common_go_proto"

	afgocrypto "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
	"github.com/hyperledger/aries-framework-go/spi/kms"
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

// BuildDIDKeyByKeyType creates a did key for pubKeyBytes based on the kms keyType.
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

		ecKey, err := afgocrypto.ToECKey(pubKey)
		if err != nil {
			return "", fmt.Errorf("buildDIDkeyByKMSKeyType failed to unmarshal key type %v: %w", keyType, err)
		}

		// used Compressed EC format for did:key, the same way as vdr key creator.
		pubKeyBytes = elliptic.MarshalCompressed(ecKey.Curve, ecKey.X, ecKey.Y)
	}

	if codec, ok := keyTypeCodecs[keyType]; ok {
		didKey, _ := fingerprint.CreateDIDKeyByCode(codec, pubKeyBytes)

		return didKey, nil
	}

	return "", fmt.Errorf("keyType '%s' does not have a multi-base codec", keyType)
}

// EncryptionPubKeyFromDIDKey parses the did:key DID and returns the key's raw value.
// note: for NIST P ECDSA keys, the raw value does not have the compression point.
//
//	In order to use elliptic.Unmarshal() with the raw value, the uncompressed point ([]byte{4}) must be prepended.
//	see https://github.com/golang/go/blob/master/src/crypto/elliptic/elliptic.go#L384.
//
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
		kmtKT = kms.ECDSAP256IEEEP1363
		kt = "EC"
		crv, x, y, pubKey = unmarshalECKey(elliptic.P256(), pubKey)
	case fingerprint.P384PubKeyMultiCodec:
		kmtKT = kms.ECDSAP384IEEEP1363
		kt = "EC"
		crv, x, y, pubKey = unmarshalECKey(elliptic.P384(), pubKey)
	case fingerprint.P521PubKeyMultiCodec:
		kmtKT = kms.ECDSAP521TypeIEEEP1363
		kt = "EC"
		crv, x, y, pubKey = unmarshalECKey(elliptic.P521(), pubKey)
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

func unmarshalECKey(ecCRV elliptic.Curve, pubKey []byte) (string, []byte, []byte, []byte) {
	var (
		x []byte
		y []byte
	)

	ecCurves := map[elliptic.Curve]string{
		elliptic.P256(): commonpb.EllipticCurveType_NIST_P256.String(),
		elliptic.P384(): commonpb.EllipticCurveType_NIST_P384.String(),
		elliptic.P521(): commonpb.EllipticCurveType_NIST_P521.String(),
	}

	xBig, yBig := elliptic.UnmarshalCompressed(ecCRV, pubKey)
	if xBig != nil && yBig != nil {
		x = xBig.Bytes()
		y = yBig.Bytes()

		// need to marshal pubKey in uncompressed format for CreateKID() call in EncryptionPubKeyFromDIDKey above since
		// did:key uses compressed elliptic format.
		pubKey = elliptic.Marshal(ecCRV, xBig, yBig)
	} else { // try normal Unmarshal if compressed returned nil xBig and yBig.
		// add compression byte for uncompressed key, comment of fingerprint.PubKeyFromDIDKey().
		pubKey = append([]byte{4}, pubKey...)
		xBig, yBig = elliptic.Unmarshal(ecCRV, pubKey)

		x = xBig.Bytes()
		y = yBig.Bytes()
	}

	return ecCurves[ecCRV], x, y, pubKey
}

func extractRawKey(didKey string) ([]byte, uint64, error) {
	idMethodSpecificID, err := fingerprint.MethodIDFromDIDKey(didKey)
	if err != nil {
		return nil, 0, fmt.Errorf("extractRawKey: MethodIDFromDIDKey failure: %w", err)
	}

	pubKey, code, err := fingerprint.PubKeyFromFingerprint(idMethodSpecificID)
	if err != nil {
		return nil, 0, fmt.Errorf("extractRawKey: PubKeyFromFingerprint failure: %w", err)
	}

	return pubKey, code, nil
}

// GetBase58PubKeyFromDIDKey parses the did:key DID and returns the key's base58 encoded value.
func GetBase58PubKeyFromDIDKey(didKey string) (string, error) {
	key, err := EncryptionPubKeyFromDIDKey(didKey)
	if err != nil {
		return "", fmt.Errorf("GetBase58PubKeyFromDIDKey: failed to parse public key bytes from "+
			"%s: %w", didKey, err)
	}

	return base58.Encode(key.X), nil
}
