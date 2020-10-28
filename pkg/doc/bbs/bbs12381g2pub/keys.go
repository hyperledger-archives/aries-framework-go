/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/phoreproject/bls"
	"github.com/phoreproject/bls/g2pubs"
	"golang.org/x/crypto/hkdf"
)

const (
	seedSize        = frCompressedSize
	generateKeySalt = "BBS-SIG-KEYGEN-SALT-"
)

// PublicKey defines BLS Public Key.
type PublicKey struct {
	PubKey *g2pubs.PublicKey
}

// PrivateKey defines BLS Public Key.
type PrivateKey struct {
	PrivKey *g2pubs.SecretKey
}

// GetFRElement returns FR element of the PrivateKey.
func (k *PrivateKey) GetFRElement() *bls.FR {
	return k.PrivKey.GetFRElement()
}

// UnmarshalPrivateKey unmarshals PrivateKey.
func UnmarshalPrivateKey(privKeyBytes []byte) (*PrivateKey, error) {
	if len(privKeyBytes) != frCompressedSize {
		return nil, errors.New("invalid size of private key")
	}

	fr, err := parseFr(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return &PrivateKey{
		PrivKey: g2pubs.NewSecretKeyFromFR(fr),
	}, nil
}

// Marshal marshals PrivateKey.
func (k *PrivateKey) Marshal() ([]byte, error) {
	bytes := k.PrivKey.Serialize()
	return bytes[:], nil
}

// PublicKey returns a Public Key as G2 point generated from the Private Key.
func (k *PrivateKey) PublicKey() *PublicKey {
	pubKeyG2Point := bls.G2AffineOne.MulFR(k.PrivKey.GetFRElement().ToRepr())

	return &PublicKey{g2pubs.NewPublicKeyFromG2(pubKeyG2Point.ToAffine())}
}

// UnmarshalPublicKey parses a PublicKey from bytes.
func UnmarshalPublicKey(pubKeyBytes []byte) (*PublicKey, error) {
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

// Marshal marshals PublicKey.
func (pk *PublicKey) Marshal() ([]byte, error) {
	pkBytes := pk.PubKey.Serialize()

	return pkBytes[:], nil
}

// GetPoint returns G2 point of the PublicKey.
func (pk *PublicKey) GetPoint() *bls.G2Projective {
	return pk.PubKey.GetPoint()
}

// GenerateKeyPair generates BBS+ PublicKey and PrivateKey pair.
func GenerateKeyPair(h func() hash.Hash, seed []byte) (*PublicKey, *PrivateKey, error) {
	if len(seed) != 0 && len(seed) != seedSize {
		return nil, nil, errors.New("invalid size of seed")
	}

	okm, err := generateOKM(seed, h)
	if err != nil {
		return nil, nil, err
	}

	privKeyFr, err := frFromOKM(okm)
	if err != nil {
		return nil, nil, fmt.Errorf("convert OKM to FR: %w", err)
	}

	privKey := &PrivateKey{PrivKey: g2pubs.NewSecretKeyFromFR(privKeyFr)}
	pubKey := privKey.PublicKey()

	return pubKey, privKey, nil
}

func generateOKM(ikm []byte, h func() hash.Hash) ([]byte, error) {
	salt := []byte(generateKeySalt)
	info := make([]byte, 2)

	if ikm != nil {
		ikm = append(ikm, 0)
	} else {
		ikm = make([]byte, seedSize+1)

		_, err := rand.Read(ikm)
		if err != nil {
			return nil, err
		}

		ikm[seedSize] = 0
	}

	return newHKDF(h, ikm, salt, info, frUncompressedSize)
}

func newHKDF(h func() hash.Hash, ikm, salt, info []byte, length int) ([]byte, error) {
	reader := hkdf.New(h, ikm, salt, info)
	result := make([]byte, length)

	_, err := io.ReadFull(reader, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
