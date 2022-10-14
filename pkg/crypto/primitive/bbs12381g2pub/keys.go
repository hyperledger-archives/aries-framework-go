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

	bls12381 "github.com/kilic/bls12-381"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	bls12381intern "github.com/hyperledger/aries-framework-go/internal/third_party/kilic/bls12-381"
)

const (
	seedSize        = frCompressedSize
	generateKeySalt = "BBS-SIG-KEYGEN-SALT-"
	csId            = "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_"
	seedDST         = csId + "SIG_GENERATOR_SEED_"
	generatorDST    = csId + "SIG_GENERATOR_DST_"
	generatorSeed   = csId + "MESSAGE_GENERATOR_SEED"
	h2s_dst         = csId + "H2S_"
	expandLen       = (384 + 128) / 8
	seedLen         = ((251 + 128) + 7) / 8
)

// PublicKey defines BLS Public Key.
type PublicKey struct {
	PointG2 *bls12381.PointG2
}

// PrivateKey defines BLS Public Key.
type PrivateKey struct {
	FR *bls12381.Fr
}

// PublicKeyWithGenerators extends PublicKey with a blinding generator h0, a commitment to the secret key w,
// and a generator for each message h.
type PublicKeyWithGenerators struct {
	Q1 *bls12381.PointG1
	Q2 *bls12381.PointG1
	H  []*bls12381.PointG1

	w *bls12381.PointG2

	messagesCount int

	domain *bls12381.Fr
}

// ToPublicKeyWithGenerators creates PublicKeyWithGenerators from the PublicKey.
func (pk *PublicKey) ToPublicKeyWithGenerators(messagesCount int) (*PublicKeyWithGenerators, error) {
	genCnt := messagesCount + 2

	generators := make([]*bls12381.PointG1, genCnt)

	n := uint32(1)
	v, _ := bls12381intern.ExpandMsgXOF(sha3.NewShake256(), []byte(generatorSeed), []byte(seedDST), seedLen)
	for i := 0; i < genCnt; i++ {
		v = append(v, i2os4(n)...)
		v, _ = bls12381intern.ExpandMsgXOF(sha3.NewShake256(), v, []byte(seedDST), seedLen)
		n++

		//TODO check if candidate is uniq
		generators[i], _ = hashToG1(v, []byte(generatorDST))
	}

	domain_builder := newEcnodeForHashBuilder()
	domain_builder.addPointG2(pk.PointG2)
	domain_builder.addInt(messagesCount)
	for _, gen := range generators {
		domain_builder.addPointG1(gen)
	}
	domain_builder.addBytes([]byte(csId))
	//TODO header ??

	domain := Hash2scalar(domain_builder.build())

	return &PublicKeyWithGenerators{
		Q1:            generators[0],
		Q2:            generators[1],
		H:             generators[2:],
		w:             pk.PointG2,
		messagesCount: messagesCount,
		domain:        domain,
	}, nil
}

func hashToG1(data []byte, dst []byte) (*bls12381.PointG1, error) {
	g := bls12381intern.NewG1()

	p, err := g.HashToCurveGenericXOF(data, dst, sha3.NewShake256())
	if err != nil {
		return nil, err
	}

	return g1.FromBytes(g.ToBytes(p))
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
	bytes := k.FR.ToBytes()
	return bytes, nil
}

// PublicKey returns a Public Key as G2 point generated from the Private Key.
func (k *PrivateKey) PublicKey() *PublicKey {
	pointG2 := g2.One()
	g2.MulScalar(pointG2, pointG2, frToRepr(k.FR))

	return &PublicKey{pointG2}
}

// UnmarshalPublicKey parses a PublicKey from bytes.
func UnmarshalPublicKey(pubKeyBytes []byte) (*PublicKey, error) {
	if len(pubKeyBytes) != bls12381G2PublicKeyLen {
		return nil, errors.New("invalid size of public key")
	}

	pointG2, err := g2.FromCompressed(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("deserialize public key: %w", err)
	}

	return &PublicKey{
		PointG2: pointG2,
	}, nil
}

// Marshal marshals PublicKey.
func (pk *PublicKey) Marshal() ([]byte, error) {
	pkBytes := g2.ToCompressed(pk.PointG2)

	return pkBytes, nil
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

	privKeyFr := frFromOKM(okm)

	privKey := &PrivateKey{privKeyFr}
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

func Hash2scalar(message []byte) *bls12381.Fr {
	return Hash2scalars(message, 1)[0]
}

func Hash2scalars(msg []byte, cnt int) []*bls12381.Fr {
	bufLen := cnt * expandLen
	msgLen := len(msg)

	msgExt := make([]byte, msgLen+1+4)
	copy(msgExt, msg)
	copy(msgExt[msgLen+1:], i2os4(uint32(msgLen)))

	out := make([]*bls12381.Fr, cnt)
	for round, completed := byte(0), false; !completed; {
		msgExt[msgLen] = round
		buf, _ := bls12381intern.ExpandMsgXOF(sha3.NewShake256(), msgExt, []byte(h2s_dst), bufLen)

		ok := true
		for i := 0; i < cnt && ok; i++ {
			out[i] = bls12381.NewFr().FromBytes(buf[i*expandLen : (i+1)*expandLen])
			ok = !out[i].IsZero()
		}
		completed = ok
	}
	return out
}
