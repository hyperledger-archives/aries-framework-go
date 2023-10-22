/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package bbsplusthresholdpub contains BBS+ threshold signing primitives and keys. Although it can be used directly, it is recommended
// to use BBS+ keys created by the kms along with the framework's Crypto service.
//
// The default local Crypto service is found at:
// "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
//
// While the remote Crypto service is found at:
// "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/webkms"
package bbsplusthresholdpub

import (
	"errors"
	"fmt"
	"sort"
)

// BBSThresholdPartyPub defines Threshold BBS+ signature scheme where public key is a point in the field of G2.
// BBS+ signature scheme (as defined in https://eprint.iacr.org/2016/663.pdf, section 4.3).
type BBSThresholdPartyPub struct{}

// New creates a new BBSThresholdPub.
func NewParty() *BBSThresholdPartyPub {
	return &BBSThresholdPartyPub{}
}

var (
	// nolint:gochecknoglobals
	// Partial signature length.
	bbsplusPartialSignatureLen = curve.CompressedG1ByteSize + 3*frCompressedSize

	// nolint:gochecknoglobals
	// Partial signature length.
	bbsplusThresholdLivePresignatureLen = curve.CompressedG1ByteSize + 3*frCompressedSize
)

// SignWithPresignature signs the one or more messages using BBS+ key pair.
func (*BBSThresholdPartyPub) SignWithPresignature(
	messages [][]byte,
	partyPrivKey []byte,
	indices []int,
	presignature *PerPartyPresignature) ([]byte, error) {

	var err error
	privKey, err := UnmarshalPartyPrivateKey(partyPrivKey)
	if err != nil {
		return nil, err
	}

	pubKey := privKey.PublicKey()
	messagesCount := len(messages)

	pubKeyWithGenerators, err := pubKey.ToPublicKeyWithGenerators(messagesCount)
	if err != nil {
		return nil, fmt.Errorf("build generators from public key: %w", err)
	}

	messagesFr := make([]*SignatureMessage, len(messages))
	for i := range messages {
		messagesFr[i] = ParseSignatureMessage(messages[i])
	}

	livePresignature := NewLivePresignature(privKey.Index+1, indices, presignature)
	// message-dependent term
	basis := curve.GenG1
	basis = basis.Mul(curve.NewZrFromInt(1))

	for i := 0; i < len(pubKeyWithGenerators.h); i++ {
		tmp := pubKeyWithGenerators.h[i].Copy()
		tmp = tmp.Mul(messagesFr[i].FR)
		basis.Add(tmp)
	}

	// Share of A
	capitalAShare := basis.Copy()
	capitalAShare = capitalAShare.Mul(livePresignature.AShare)
	tmp := pubKeyWithGenerators.h0.Copy()
	tmp = tmp.Mul(livePresignature.AlphaShare)
	capitalAShare.Add(tmp)

	partialSignature := &PartialSignature{
		CapitalAShare: capitalAShare,
		DeltaShare:    livePresignature.DeltaShare,
		EShare:        livePresignature.EShare,
		SShare:        livePresignature.SShare,
	}

	return partialSignature.ToBytes()
}

// Verify makes BLS BBS12-381 signature verification.
func (bbs *BBSThresholdPartyPub) Verify(messages [][]byte, sigBytes, pubKeyBytes []byte) error {
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

	messagesFr := messagesToFr(messages)

	return signature.Verify(messagesFr, publicKeyWithGenerators)
}

// VerifyProof verifies BBS+ signature proof for one ore more revealed messages.
func (bbs *BBSThresholdPartyPub) VerifyProof(messagesBytes [][]byte, proof, nonce, pubKeyBytes []byte) error {
	payload, err := parsePoKPayload(proof)
	if err != nil {
		return fmt.Errorf("parse signature proof: %w", err)
	}

	signatureProof, err := ParseSignatureProof(proof[payload.lenInBytes():])
	if err != nil {
		return fmt.Errorf("parse signature proof: %w", err)
	}

	messages := messagesToFr(messagesBytes)

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

	challengeBytes := signatureProof.GetBytesForChallenge(revealedMessages, publicKeyWithGenerators)
	proofNonce := ParseProofNonce(nonce)
	proofNonceBytes := proofNonce.ToBytes()
	challengeBytes = append(challengeBytes, proofNonceBytes...)
	proofChallenge := frFromOKM(challengeBytes)

	return signatureProof.Verify(proofChallenge, publicKeyWithGenerators, revealedMessages, messages)
}

// DeriveProof derives a proof of BBS+ signature with some messages disclosed.
func (bbs *BBSThresholdPartyPub) DeriveProof(messages [][]byte, sigBytes, nonce, pubKeyBytes []byte,
	revealedIndexes []int) ([]byte, error) {
	if len(revealedIndexes) == 0 {
		return nil, errors.New("no message to reveal")
	}

	sort.Ints(revealedIndexes)

	messagesCount := len(messages)

	messagesFr := messagesToFr(messages)

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

	challengeBytes := pokSignature.ToBytes()

	proofNonce := ParseProofNonce(nonce)
	proofNonceBytes := proofNonce.ToBytes()
	challengeBytes = append(challengeBytes, proofNonceBytes...)

	proofChallenge := frFromOKM(challengeBytes)

	proof := pokSignature.GenerateProof(proofChallenge)

	payload := newPoKPayload(messagesCount, revealedIndexes)

	payloadBytes, err := payload.toBytes()
	if err != nil {
		return nil, fmt.Errorf("derive proof: paylod to bytes: %w", err)
	}

	signatureProofBytes := append(payloadBytes, proof.ToBytes()...)

	return signatureProofBytes, nil
}
