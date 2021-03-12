/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fingerprint

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

const (
	// X25519PubKeyMultiCodec for Curve25519 public key in multicodec table.
	// source: https://github.com/multiformats/multicodec/blob/master/table.csv.
	X25519PubKeyMultiCodec = 0xec
	// ED25519PubKeyMultiCodec for Ed25519 public key in multicodec table.
	ED25519PubKeyMultiCodec = 0xed
	// BLS12381g2PubKeyMultiCodec for BLS12-381 G2 public key in multicodec table.
	BLS12381g2PubKeyMultiCodec = 0xeb
	// BLS12381g1g2PubKeyMultiCodec for BLS12-381 G1G2 public key in multicodec table.
	BLS12381g1g2PubKeyMultiCodec = 0xee
	// P256PubKeyMultiCodec for NIST P-256 public key in multicodec table.
	P256PubKeyMultiCodec = 0x1200
	// P384PubKeyMultiCodec for NIST P-384 public key in multicodec table.
	P384PubKeyMultiCodec = 0x1201
	// P521PubKeyMultiCodec for NIST P-521 public key in multicodec table.
	P521PubKeyMultiCodec = 0x1202

	// Default BLS 12-381 public key length in G2 field.
	bls12381G2PublicKeyLen = 96

	// Number of bytes in G1 X coordinate.
	g1CompressedSize = 48
)

// CreateDIDKey calls CreateDIDKeyByCode with Ed25519 key code.
func CreateDIDKey(pubKey []byte) (string, string) {
	return CreateDIDKeyByCode(ED25519PubKeyMultiCodec, pubKey)
}

// CreateDIDKeyByCode creates a did:key ID using the multicodec key fingerprint as per the did:key format spec found at:
// https://w3c-ccg.github.io/did-method-key/#format.
func CreateDIDKeyByCode(code uint64, pubKey []byte) (string, string) {
	methodID := KeyFingerprint(code, pubKey)
	didKey := fmt.Sprintf("did:key:%s", methodID)
	keyID := fmt.Sprintf("%s#%s", didKey, methodID)

	return didKey, keyID
}

// KeyFingerprint generates a multicode fingerprint for pubKeyValue (raw key []byte).
// It is mainly used as the controller ID (methodSpecification ID) of a did key.
func KeyFingerprint(code uint64, pubKeyValue []byte) string {
	multicodecValue := multicodec(code)
	mcLength := len(multicodecValue)
	buf := make([]uint8, mcLength+len(pubKeyValue))
	copy(buf, multicodecValue)
	copy(buf[mcLength:], pubKeyValue)

	return fmt.Sprintf("z%s", base58.Encode(buf))
}

func multicodec(code uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	bw := binary.PutUvarint(buf, code)

	return buf[:bw]
}

// PubKeyFromFingerprint extracts the raw public key from a did:key fingerprint.
func PubKeyFromFingerprint(fingerprint string) ([]byte, uint64, error) {
	// did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))
	// https://w3c-ccg.github.io/did-method-key/#format
	const maxMulticodecBytes = 9

	if len(fingerprint) < 2 || fingerprint[0] != 'z' {
		return nil, 0, errors.New("unknown key encoding")
	}

	mc := base58.Decode(fingerprint[1:]) // skip leading "z"

	code, br := binary.Uvarint(mc)
	if br == 0 {
		return nil, 0, errors.New("unknown key encoding")
	}

	if br > maxMulticodecBytes {
		return nil, 0, errors.New("code exceeds maximum size")
	}

	if code == BLS12381g1g2PubKeyMultiCodec {
		// for BBS+ G1G2 did:key type, return the G2 public key only (discard G1 key for now).
		if len(mc[br+g1CompressedSize:]) != bls12381G2PublicKeyLen {
			return nil, 0, errors.New("invalid bbs+ public key")
		}

		return mc[br+g1CompressedSize:], code, nil
	}

	return mc[br:], code, nil
}

// PubKeyFromDIDKey parses the did:key DID and returns the key's raw value.
// note: for NIST P ECDSA keys, the raw value does not have the compression point.
//	In order to use elliptic.Unmarshal() with the raw value, the uncompressed point ([]byte{4}) must be prepended.
//	see https://github.com/golang/go/blob/master/src/crypto/elliptic/elliptic.go#L319.
func PubKeyFromDIDKey(didKey string) ([]byte, error) {
	id, err := did.Parse(didKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse did:key [%s]: %w", didKey, err)
	}

	// did:key is hard-coded to base58btc:
	// - https://w3c-ccg.github.io/did-method-key/
	// - https://github.com/multiformats/multibase#multibase-table
	if !strings.HasPrefix(id.MethodSpecificID, "z") {
		return nil, fmt.Errorf("not a valid did:key identifier (not a base58btc multicodec): %s", didKey)
	}

	pubKey, code, err := PubKeyFromFingerprint(id.MethodSpecificID)
	if err != nil {
		return nil, err
	}

	switch code {
	case X25519PubKeyMultiCodec, ED25519PubKeyMultiCodec, BLS12381g2PubKeyMultiCodec, BLS12381g1g2PubKeyMultiCodec,
		P256PubKeyMultiCodec, P384PubKeyMultiCodec, P521PubKeyMultiCodec:
		break
	default:
		return nil, fmt.Errorf("unsupported key multicodec code [0x%x]", code)
	}

	return pubKey, nil
}
