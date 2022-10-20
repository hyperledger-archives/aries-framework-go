/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package bbs12381g2pub contains BBS+ signing primitives and keys. Although it can be used directly, it is recommended
// to use BBS+ keys created by the kms along with the framework's Crypto service.
// The default local Crypto service is found at: "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
// while the remote Crypto service is found at: "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
package bbs12381g2pub

import (
	"errors"
	"fmt"
	"sort"

	bls12381 "github.com/kilic/bls12-381"
)

// nolint:gochecknoglobals
var (
	g1 = bls12381.NewG1()
	g2 = bls12381.NewG2()
)

// BBSG2Pub defines BBS+ signature scheme where public key is a point in the field of G2.
// BBS+ signature scheme (as defined in https://eprint.iacr.org/2016/663.pdf, section 4.3).
type BBSG2Pub struct{}

// New creates a new BBSG2Pub.
func New() *BBSG2Pub {
	return &BBSG2Pub{}
}

const (
	// Signature length.
	bls12381SignatureLen = 112

	// Default BLS 12-381 public key length in G2 field.
	bls12381G2PublicKeyLen = 96

	// Number of bytes in G1 X coordinate.
	g1CompressedSize = 48

	// Number of bytes in scalar compressed form.
	frCompressedSize = 32

	// Number of bytes in scalar uncompressed form.
	frUncompressedSize = 48

	// Ciphersuite ID for BLS12-381 and SHAKE-256 combination.
	csID = "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_"
)

// Verify makes BLS BBS12-381 signature verification.
func (bbs *BBSG2Pub) Verify(messages [][]byte, sigBytes, pubKeyBytes []byte) error {
	signature, err := ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}

	pubKey, err := UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	messagesCount := len(messages)

	publicKeyWithGenerators, err := pubKey.ToPublicKeyWithGenerators(messagesCount)
	if err != nil {
		return fmt.Errorf("build generators from public key: %w", err)
	}

	messagesFr := ParseSignatureMessages(messages)

	return signature.Verify(messagesFr, publicKeyWithGenerators)
}

// Sign signs the one or more messages using private key in compressed form.
func (bbs *BBSG2Pub) Sign(messages [][]byte, privKeyBytes []byte) ([]byte, error) {
	privKey, err := UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal private key: %w", err)
	}

	if len(messages) == 0 {
		return nil, errors.New("messages are not defined")
	}

	return bbs.SignWithKey(messages, privKey)
}

// VerifyProof verifies BBS+ signature proof for one ore more revealed messages.
func (bbs *BBSG2Pub) VerifyProof(messagesBytes [][]byte, proof, nonce, pubKeyBytes []byte) error {
	payload, err := parsePoKPayload(proof)
	if err != nil {
		return fmt.Errorf("parse signature proof: %w", err)
	}

	signatureProof, err := ParseSignatureProof(proof[payload.lenInBytes():])
	if err != nil {
		return fmt.Errorf("parse signature proof: %w", err)
	}

	messages := ParseSignatureMessages(messagesBytes)

	pubKey, err := UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	publicKeyWithGenerators, err := pubKey.ToPublicKeyWithGenerators(payload.messagesCount)
	if err != nil {
		return fmt.Errorf("build generators from public key: %w", err)
	}

	if len(payload.revealed) > len(messages) {
		return fmt.Errorf("payload revealed bigger from messages")
	}

	revealedMessages := make(map[int]*SignatureMessage)
	for i := range payload.revealed {
		revealedMessages[payload.revealed[i]] = messages[i]
	}

	challenge := signatureProof.CalculateChallenge(revealedMessages, publicKeyWithGenerators, nonce)

	return signatureProof.Verify(challenge, publicKeyWithGenerators, revealedMessages, messages)
}

// DeriveProof derives a proof of BBS+ signature with some messages disclosed.
func (bbs *BBSG2Pub) DeriveProof(messages [][]byte, sigBytes, nonce, pubKeyBytes []byte,
	revealedIndexes []int) ([]byte, error) {
	if len(revealedIndexes) == 0 {
		return nil, errors.New("no message to reveal")
	}

	sort.Ints(revealedIndexes)

	messagesCount := len(messages)

	messagesFr := ParseSignatureMessages(messages)

	pubKey, err := UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	publicKeyWithGenerators, err := pubKey.ToPublicKeyWithGenerators(messagesCount)
	if err != nil {
		return nil, fmt.Errorf("build generators from public key: %w", err)
	}

	signature, err := ParseSignature(sigBytes)
	if err != nil {
		return nil, fmt.Errorf("parse signature: %w", err)
	}

	pokSignature, err := NewPoKOfSignature(signature, messagesFr, revealedIndexes, publicKeyWithGenerators)
	if err != nil {
		return nil, fmt.Errorf("init proof of knowledge signature: %w", err)
	}

	proofChallenge := pokSignature.CalculateChallenge(messagesCount, publicKeyWithGenerators.domain, nonce)

	proof := pokSignature.GenerateProof(proofChallenge)

	payload := newPoKPayload(messagesCount, revealedIndexes)

	payloadBytes, err := payload.toBytes()
	if err != nil {
		return nil, fmt.Errorf("derive proof: paylod to bytes: %w", err)
	}

	signatureProofBytes := append(payloadBytes, proof.ToBytes()...)

	return signatureProofBytes, nil
}

// SignWithKey signs the one or more messages using BBS+ key pair.
func (bbs *BBSG2Pub) SignWithKey(messages [][]byte, privKey *PrivateKey) ([]byte, error) {
	var err error

	pubKey := privKey.PublicKey()
	messagesCount := len(messages)

	pubKeyWithGenerators, err := pubKey.ToPublicKeyWithGenerators(messagesCount)
	if err != nil {
		return nil, fmt.Errorf("build generators from public key: %w", err)
	}

	esBuilder := newEcnodeForHashBuilder()
	esBuilder.addScalar(privKey.FR)
	esBuilder.addScalar(pubKeyWithGenerators.domain)

	for _, msg := range messages {
		esBuilder.addBytes(msg)
	}

	es := Hash2scalars(esBuilder.build(), 2)
	e, s := es[0], es[1]
	exp := bls12381.NewFr().Set(privKey.FR)
	exp.Add(exp, e)
	exp.Inverse(exp)

	messagesFr := ParseSignatureMessages(messages)
	b := computeB(s, messagesFr, pubKeyWithGenerators)

	sig := g1.New()
	g1.MulScalar(sig, b, frToRepr(exp))

	signature := &Signature{
		A: sig,
		E: e,
		S: s,
	}

	return signature.ToBytes()
}

func computeB(s *bls12381.Fr, messages []*SignatureMessage, key *PublicKeyWithGenerators) *bls12381.PointG1 {
	const basesOffset = 2

	bindingBasis := g1.One()
	bindingExp := bls12381.NewFr().One()

	cb := newCommitmentBuilder(len(messages) + basesOffset)

	cb.add(bindingBasis, bindingExp)
	cb.add(key.q1, s)
	cb.add(key.q2, key.domain)

	for i := 0; i < len(messages); i++ {
		cb.add(key.h[i], messages[i].FR)
	}

	return cb.build()
}

type commitmentBuilder struct {
	bases   []*bls12381.PointG1
	scalars []*bls12381.Fr
}

func newCommitmentBuilder(expectedSize int) *commitmentBuilder {
	return &commitmentBuilder{
		bases:   make([]*bls12381.PointG1, 0, expectedSize),
		scalars: make([]*bls12381.Fr, 0, expectedSize),
	}
}

func (cb *commitmentBuilder) add(base *bls12381.PointG1, scalar *bls12381.Fr) {
	cb.bases = append(cb.bases, base)
	cb.scalars = append(cb.scalars, scalar)
}

func (cb *commitmentBuilder) build() *bls12381.PointG1 {
	return sumOfG1Products(cb.bases, cb.scalars)
}

func sumOfG1Products(bases []*bls12381.PointG1, scalars []*bls12381.Fr) *bls12381.PointG1 {
	res := g1.Zero()

	for i := 0; i < len(bases); i++ {
		b := bases[i]
		s := scalars[i]

		g := g1.New()

		g1.MulScalar(g, b, frToRepr(s))
		g1.Add(res, res, g)
	}

	return res
}

func compareTwoPairings(p1 *bls12381.PointG1, q1 *bls12381.PointG2,
	p2 *bls12381.PointG1, q2 *bls12381.PointG2) bool {
	engine := bls12381.NewEngine()

	engine.AddPair(p1, q1)
	engine.AddPair(p2, q2)

	return engine.Check()
}

// ProofNonce is a nonce for Proof of Knowledge proof.
type ProofNonce struct {
	fr *bls12381.Fr
}

// ParseProofNonce creates a new ProofNonce from bytes.
func ParseProofNonce(proofNonceBytes []byte) *ProofNonce {
	return &ProofNonce{
		frFromOKM(proofNonceBytes),
	}
}

// ToBytes converts ProofNonce into bytes.
func (pn *ProofNonce) ToBytes() []byte {
	return frToRepr(pn.fr).ToBytes()
}

type encodeForHashBuilder struct {
	bytes []byte // TODO check encoding functions per type below
}

func newEcnodeForHashBuilder() *encodeForHashBuilder {
	return &encodeForHashBuilder{
		bytes: make([]byte, 0),
	}
}

func (db *encodeForHashBuilder) addInt(value int) {
	db.bytes = append(db.bytes, uint64ToBytes(uint64(value))...)
}

func (db *encodeForHashBuilder) addPointG1(value *bls12381.PointG1) {
	db.bytes = append(db.bytes, g1.ToBytes(value)...)
}

func (db *encodeForHashBuilder) addPointG2(value *bls12381.PointG2) {
	db.bytes = append(db.bytes, g2.ToBytes(value)...)
}

func (db *encodeForHashBuilder) addScalar(value *bls12381.Fr) {
	db.bytes = append(db.bytes, value.ToBytes()...)
}

func (db *encodeForHashBuilder) addBytes(value []byte) {
	db.bytes = append(db.bytes, uint64ToBytes(uint64(len(value)))...)
	db.bytes = append(db.bytes, value...)
}

func (db *encodeForHashBuilder) build() []byte {
	return db.bytes
}
