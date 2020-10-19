/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"fmt"

	commonpb "github.com/google/tink/go/proto/common_go_proto"

	compositepb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
)

// package composite provides the core crypto composite primitives such as ECDH-ES and ECDH-1PU to be used by JWE crypto

const (
	// A256GCM is the default content encryption algorithm value as per
	// the JWA specification: https://tools.ietf.org/html/rfc7518#section-5.1
	A256GCM = "A256GCM"
	// DIDCommEncType representing the JWE 'Typ' protected type header.
	DIDCommEncType = "didcomm-envelope-enc"
)

// EncryptedData represents the Encryption's output data as a result of ECDHESEncrypt.Encrypt(pt, aad) call
// The user of the primitive must unmarshal the result and build their own ECDH-ES compliant message (ie JWE msg).
type EncryptedData struct {
	EncAlg     string                 `json:"encalg,omitempty"`
	EncType    string                 `json:"enctype,omitempty"`
	Ciphertext []byte                 `json:"ciphertext,omitempty"`
	IV         []byte                 `json:"iv,omitempty"`
	Tag        []byte                 `json:"tag,omitempty"`
	Recipients []*RecipientWrappedKey `json:"recipients,omitempty"`
	// SingleRecipientAAD is the result of an AAD update using a single recipient JWE envelope with recipient headers.
	// The JWE encrypter in this framework rebuilds this AAD value when building/parsing the JWE envelope. It does not
	// use this field. It is added here to provide access to the updated AAD for single recipient encryption use by
	// external users of this crypto primitive.
	SingleRecipientAAD []byte `json:"singlerecipientaad,omitempty"`
}

// RecipientWrappedKey contains recipient key material required to unwrap CEK.
type RecipientWrappedKey struct {
	KID          string    `json:"kid,omitempty"`
	EncryptedCEK []byte    `json:"encryptedcek,omitempty"`
	EPK          PublicKey `json:"epk,omitempty"`
	Alg          string    `json:"alg,omitempty"`
}

// PublicKey mainly to exchange EPK in RecipientWrappedKey.
type PublicKey struct {
	KID   string `json:"kid,omitempty"`
	X     []byte `json:"x,omitempty"`
	Y     []byte `json:"y,omitempty"`
	Curve string `json:"curve,omitempty"`
	Type  string `json:"type,omitempty"`
}

// GetCurveType is a utility function that converts a string EC curve name into an EC curve proto type.
func GetCurveType(curve string) (commonpb.EllipticCurveType, error) {
	switch curve {
	case "secp256r1", "NIST_P256", "P-256", "EllipticCurveType_NIST_P256":
		return commonpb.EllipticCurveType_NIST_P256, nil
	case "secp384r1", "NIST_P384", "P-384", "EllipticCurveType_NIST_P384":
		return commonpb.EllipticCurveType_NIST_P384, nil
	case "secp521r1", "NIST_P521", "P-521", "EllipticCurveType_NIST_P521":
		return commonpb.EllipticCurveType_NIST_P521, nil
	default:
		return commonpb.EllipticCurveType_UNKNOWN_CURVE, fmt.Errorf("curve %s not supported", curve)
	}
}

// GetKeyType is a utility function that converts a string type value into an proto KeyType.
func GetKeyType(keyType string) (compositepb.KeyType, error) {
	switch keyType {
	case "EC":
		return compositepb.KeyType_EC, nil
	case "OKP":
		return compositepb.KeyType_OKP, nil
	default:
		return compositepb.KeyType_UNKNOWN_KEY_TYPE, fmt.Errorf("key type %s not supported", keyType)
	}
}
