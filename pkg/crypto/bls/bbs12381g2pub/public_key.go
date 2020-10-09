/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"errors"
	"fmt"

	"github.com/phoreproject/bls"
	"github.com/phoreproject/bls/g2pubs"
)

// PublicKey defines BLS Public Key.
type PublicKey struct {
	PubKey *g2pubs.PublicKey
}

// ParsePublicKey parses a PublicKey from bytes.
func ParsePublicKey(pubKeyBytes []byte) (*PublicKey, error) {
	if len(pubKeyBytes) != bls12381G2PublicKeyLen {
		return nil, errors.New("invalid size of public key")
	}

	var pkBytesArr [bls12381G2PublicKeyLen]byte
	copy(pkBytesArr[:], pubKeyBytes[:bls12381G2PublicKeyLen])

	publicKey, err := g2pubs.DeserializePublicKey(pkBytesArr)
	if err != nil {
		return nil, fmt.Errorf("deserialize public key: %w", err)
	}

	return &PublicKey{
		PubKey: publicKey,
	}, nil
}

// GetPoint returns G1 point of the PublicKey.
func (pk *PublicKey) GetPoint() *bls.G2Projective {
	return pk.PubKey.GetPoint()
}
