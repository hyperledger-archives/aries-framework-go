/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsplusthresholdpub

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	ml "github.com/IBM/mathlib"

	"golang.org/x/crypto/hkdf"
)

var (
	// nolint:gochecknoglobals
	seedSize = frCompressedSize

	// nolint:gochecknoglobals
	generateKeySalt = "BBS-SIG-KEYGEN-SALT-"
)

// PublicKey defines BLS Public Key.
type PublicKey struct {
	PointG2 *ml.G2
}

// PrivateKey defines BLS Public Key.
type PrivateKey struct {
	FR *ml.Zr
}

type PartyPrivateKey struct {
	SKShare   *ml.Zr
	publicKey *ml.G2
	Index     int
}

func (ppk *PartyPrivateKey) Marshal() ([]byte, error) {
	skShareBytes := ppk.SKShare.Bytes()
	pkBytes := ppk.publicKey.Compressed()
	indexBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBytes, uint32(ppk.Index))
	bytes := append(skShareBytes, pkBytes...)
	bytes = append(bytes, indexBytes...)
	return bytes, nil
}

func UnmarshalPartyPrivateKey(partyPrivKeyBytes []byte) (*PartyPrivateKey, error) {
	if len(partyPrivKeyBytes) != frCompressedSize+g2CompressedSize+intSize {
		return nil, errors.New("invalid size of party private key")
	}

	publicKey, err := curve.NewG2FromCompressed(partyPrivKeyBytes[frCompressedSize : frCompressedSize+g2CompressedSize])
	if err != nil {
		return nil, err
	}

	return &PartyPrivateKey{
		SKShare:   parseFr(partyPrivKeyBytes[:frCompressedSize]),
		publicKey: publicKey,
		Index:     int(binary.LittleEndian.Uint32(partyPrivKeyBytes[frCompressedSize+g2CompressedSize:])),
	}, nil
}

func (ppk *PartyPrivateKey) PublicKey() *PublicKey {
	return &PublicKey{ppk.publicKey}
}

// PublicKeyWithGenerators extends PublicKey with a blinding generator h0, a commitment to the secret key w,
// and a generator for each message h.
type PublicKeyWithGenerators struct {
	h0 *ml.G1
	h  []*ml.G1

	w *ml.G2

	messagesCount int
}

// ToPublicKeyWithGenerators creates PublicKeyWithGenerators from the PublicKey.
func (pk *PublicKey) ToPublicKeyWithGenerators(messagesCount int) (*PublicKeyWithGenerators, error) {
	offset := g2UncompressedSize + 1

	data := calcData(pk, messagesCount)

	h0 := hashToG1(data)

	h := make([]*ml.G1, messagesCount)

	for i := 1; i <= messagesCount; i++ {
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)

		iBytes := uint32ToBytes(uint32(i))

		for j := 0; j < len(iBytes); j++ {
			dataCopy[j+offset] = iBytes[j]
		}

		h[i-1] = hashToG1(dataCopy)
	}

	return &PublicKeyWithGenerators{
		h0:            h0,
		h:             h,
		w:             pk.PointG2,
		messagesCount: messagesCount,
	}, nil
}

func calcData(key *PublicKey, messagesCount int) []byte {
	data := key.PointG2.Bytes()

	data = append(data, 0, 0, 0, 0, 0, 0)

	mcBytes := uint32ToBytes(uint32(messagesCount))

	data = append(data, mcBytes...)

	return data
}

func hashToG1(data []byte) *ml.G1 {
	var dstG1 = []byte("BLS12381G1_XMD:BLAKE2B_SSWU_RO_BBS+_SIGNATURES:1_0_0")

	return curve.HashToG1WithDomain(data, dstG1)
}

// UnmarshalPrivateKey unmarshals PrivateKey.
func UnmarshalPrivateKey(privKeyBytes []byte) (*PrivateKey, error) {
	if len(privKeyBytes) != frCompressedSize {
		return nil, errors.New("invalid size of private key")
	}

	fr := parseFr(privKeyBytes)

	return &PrivateKey{
		FR: fr,
	}, nil
}

// Marshal marshals PrivateKey.
func (k *PrivateKey) Marshal() ([]byte, error) {
	bytes := k.FR.Bytes()
	return bytes, nil
}

// PublicKey returns a Public Key as G2 point generated from the Private Key.
func (k *PrivateKey) PublicKey() *PublicKey {
	pointG2 := curve.GenG2.Mul(frToRepr(k.FR))

	return &PublicKey{pointG2}
}

// UnmarshalPublicKey parses a PublicKey from bytes.
func UnmarshalPublicKey(pubKeyBytes []byte) (*PublicKey, error) {
	if len(pubKeyBytes) != bbsplusThresholdPublicKeyLen {
		return nil, errors.New("invalid size of public key")
	}

	pointG2, err := curve.NewG2FromCompressed(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("deserialize public key: %w", err)
	}

	return &PublicKey{
		PointG2: pointG2,
	}, nil
}

// Marshal marshals PublicKey.
func (pk *PublicKey) Marshal() ([]byte, error) {
	pkBytes := pk.PointG2.Compressed()

	return pkBytes, nil
}

// GenerateKeyPair generates BBS+ PublicKey and PrivateKey pair.
func GenerateKeyPair(h func() hash.Hash, seed []byte, t, n, k int) (*PublicKey, *PrivateKey, []*PerPartyPrecomputations, error) {
	if len(seed) != 0 && len(seed) != seedSize {
		return nil, nil, nil, errors.New("invalid size of seed")
	}

	okm, err := generateOKM(seed, h)
	if err != nil {
		return nil, nil, nil, err
	}

	privKeyFr := frFromOKM(okm)
	privKey := &PrivateKey{privKeyFr}
	pubKey := privKey.PublicKey()
	output := GeneratePCFPCGOutputFromPrivKey(privKeyFr, t, k, n)
	precomputations := CreatePPPrecomputationFromVOLEEvaluation(k, n,
		pubKey.PointG2,
		output.SkShares,
		output.AShares,
		output.EShares,
		output.SShares,
		output.AeTerms,
		output.AsTerms,
		output.AskTerms,
	)

	return pubKey, privKey, precomputations, nil
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
