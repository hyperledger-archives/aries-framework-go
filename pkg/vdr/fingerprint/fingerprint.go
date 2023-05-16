/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fingerprint

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
)

const (
	// X25519PubKeyMultiCodec for Curve25519 public key in multicodec table.
	// source: https://github.com/multiformats/multicodec/blob/master/table.csv.
	X25519PubKeyMultiCodec = fingerprint.X25519PubKeyMultiCodec
	// ED25519PubKeyMultiCodec for Ed25519 public key in multicodec table.
	ED25519PubKeyMultiCodec = fingerprint.ED25519PubKeyMultiCodec
	// BLS12381g2PubKeyMultiCodec for BLS12-381 G2 public key in multicodec table.
	BLS12381g2PubKeyMultiCodec = fingerprint.BLS12381g2PubKeyMultiCodec
	// BLS12381g1g2PubKeyMultiCodec for BLS12-381 G1G2 public key in multicodec table.
	BLS12381g1g2PubKeyMultiCodec = fingerprint.BLS12381g1g2PubKeyMultiCodec
	// P256PubKeyMultiCodec for NIST P-256 public key in multicodec table.
	P256PubKeyMultiCodec = fingerprint.P256PubKeyMultiCodec
	// P384PubKeyMultiCodec for NIST P-384 public key in multicodec table.
	P384PubKeyMultiCodec = fingerprint.P384PubKeyMultiCodec
	// P521PubKeyMultiCodec for NIST P-521 public key in multicodec table.
	P521PubKeyMultiCodec = fingerprint.P521PubKeyMultiCodec
)

// CreateDIDKey calls CreateDIDKeyByCode with Ed25519 key code.
func CreateDIDKey(pubKey []byte) (string, string) {
	return fingerprint.CreateDIDKey(pubKey)
}

// CreateDIDKeyByCode creates a did:key ID using the multicodec key fingerprint as per the did:key format spec found at:
// https://w3c-ccg.github.io/did-method-key/#format. It does not parse the contents of 'pubKey'. Use
// kmsdidkey.BuildDIDKeyByKeyType() for marshalled keys extracted from the KMS instead of this function.
func CreateDIDKeyByCode(code uint64, pubKey []byte) (string, string) {
	return fingerprint.CreateDIDKeyByCode(code, pubKey)
}

// CreateDIDKeyByJwk creates a did:key ID using the multicodec key fingerprint as per the did:key format spec found at:
// https://w3c-ccg.github.io/did-method-key/#format.
func CreateDIDKeyByJwk(jsonWebKey *jwk.JWK) (string, string, error) {
	return fingerprint.CreateDIDKeyByJwk(jsonWebKey)
}

// KeyFingerprint generates a multicode fingerprint for pubKeyValue (raw key []byte).
// It is mainly used as the controller ID (methodSpecification ID) of a did key.
func KeyFingerprint(code uint64, pubKeyValue []byte) string {
	return fingerprint.KeyFingerprint(code, pubKeyValue)
}

// PubKeyFromFingerprint extracts the raw public key from a did:key fingerprint.
func PubKeyFromFingerprint(fp string) ([]byte, uint64, error) {
	return fingerprint.PubKeyFromFingerprint(fp)
}

// PubKeyFromDIDKey parses the did:key DID and returns the key's raw value.
// note: for NIST P ECDSA keys, the raw value does not have the compression point.
//
//	In order to use elliptic.Unmarshal() with the raw value, the uncompressed point ([]byte{4}) must be prepended.
//	see https://github.com/golang/go/blob/master/src/crypto/elliptic/elliptic.go#L384.
func PubKeyFromDIDKey(didKey string) ([]byte, error) {
	return fingerprint.PubKeyFromDIDKey(didKey)
}
