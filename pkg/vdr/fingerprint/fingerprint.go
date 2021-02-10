/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fingerprint

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

const (
	// source: https://github.com/multiformats/multicodec/blob/master/table.csv.
	ed25519pub = 0xed // Ed25519 public key in multicodec table
)

// CreateDIDKey creates a did:key ID using the multicodec key fingerprint as per the did:key format spec found at:
// https://w3c-ccg.github.io/did-method-key/#format.
func CreateDIDKey(pubKey []byte) (string, string) {
	methodID := KeyFingerprint(ed25519pub, pubKey)
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
	buf := make([]byte, 2)
	binary.PutUvarint(buf, code)

	return buf
}

// PubKeyFromFingerprint extracts the raw public key from a did:key fingerprint.
func PubKeyFromFingerprint(fingerprint string) ([]byte, error) {
	// did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))
	// https://w3c-ccg.github.io/did-method-key/#format
	mc := base58.Decode(fingerprint[1:]) // skip leading "z"
	if !bytes.Equal(multicodec(ed25519pub), mc[:2]) {
		return nil, fmt.Errorf("pubKeyFromFingerprint: not supported public key (multicodec code: %#x)", mc[0])
	}

	return mc[2:], nil
}

// PubKeyFromDIDKey parses the did:key DID and returns the key's raw value.
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

	return PubKeyFromFingerprint(id.MethodSpecificID)
}
