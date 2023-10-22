package signer

import (
	"errors"
	"strings"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbsplusthresholdpub"
)

type baseSignatureSigner struct {
	keyType   string
	curve     string
	algorithm string
}

func (sv baseSignatureSigner) KeyType() string {
	return sv.keyType
}

func (sv baseSignatureSigner) Curve() string {
	return sv.curve
}

func (sv baseSignatureSigner) Algorithm() string {
	return sv.algorithm
}

type ThresholdBBSG2SignaturePartySigner struct {
	partyPrivKeyBytes []byte
	indices           [][]int
	presignatures     []*bbsplusthresholdpub.PerPartyPresignature
	msgIndex          int // Index of the current message/presignature.
	baseSignatureSigner
}

func NewThresholdBBSG2SignaturePartySigner(precomputationBytes []byte) (*ThresholdBBSG2SignaturePartySigner, error) {
	precomputation, err := bbsplusthresholdpub.ParsePerPartyPrecomputations(precomputationBytes)
	if err != nil {
		return nil, err
	}
	partyPrivKey := precomputation.PartyPrivateKey()
	partyPrivKeyBytes, err := partyPrivKey.Marshal()
	if err != nil {
		return nil, err
	}
	numOfPresigs := len(precomputation.Presignatures)
	return &ThresholdBBSG2SignaturePartySigner{
		partyPrivKeyBytes: partyPrivKeyBytes,
		indices:           make([][]int, numOfPresigs),
		presignatures:     precomputation.Presignatures,
		baseSignatureSigner: baseSignatureSigner{
			keyType:   "EC",
			curve:     "BLS12381_G2",
			algorithm: "party_threshold_bbs+",
		},
	}, nil
}

func (tbps *ThresholdBBSG2SignaturePartySigner) SetIndices(indices []int, index int) {
	tbps.indices[index] = indices
}

func (tbps *ThresholdBBSG2SignaturePartySigner) SetNexMsgIndex(msgIndex int) {
	tbps.msgIndex = msgIndex
}

func (tbps *ThresholdBBSG2SignaturePartySigner) Alg() string {
	return tbps.Algorithm()
}

// Sign will sign create signature of each message and aggregate it
// into a single partial signature using the signer's precomputation.
// returns:
//
//	partial signature in []byte
//	error in case of errors
func (tbps *ThresholdBBSG2SignaturePartySigner) Sign(data []byte) ([]byte, error) {
	party_bbs := bbsplusthresholdpub.NewParty()
	if tbps.msgIndex >= len(tbps.presignatures) || tbps.msgIndex < 0 {
		return nil, errors.New("out of presignatures")
	}
	if tbps.indices[tbps.msgIndex] == nil {
		return nil, errors.New("missing indices")
	}
	partialSigBytes, err := party_bbs.SignWithPresignature(splitMessageIntoLines(string(data)),
		tbps.partyPrivKeyBytes,
		tbps.indices[tbps.msgIndex],
		tbps.presignatures[tbps.msgIndex])
	if err != nil {
		return nil, err
	}
	return partialSigBytes, nil
}

type ThresholdBBSG2SignatureSigner struct {
	threshold         int
	msgIndex          int
	partialSignatures [][]byte
	baseSignatureSigner
}

func NewThresholdBBSG2SignatureSigner(threshold, msgIndex int,
	partialSignatures [][]byte) *ThresholdBBSG2SignatureSigner {
	return &ThresholdBBSG2SignatureSigner{
		threshold:         threshold,
		msgIndex:          msgIndex,
		partialSignatures: partialSignatures,
		baseSignatureSigner: baseSignatureSigner{
			keyType:   "EC",
			curve:     "BLS12381_G2",
			algorithm: "main_threshold_bbs+",
		},
	}
}

func (tbs *ThresholdBBSG2SignatureSigner) Sign(data []byte) ([]byte, error) {
	main_bbs := bbsplusthresholdpub.New()
	sigBytes, err := main_bbs.SignWithPartialSignatures(tbs.partialSignatures)
	if err != nil {
		return nil, err
	}
	return sigBytes, nil
}

func (tbs *ThresholdBBSG2SignatureSigner) Alg() string {
	return tbs.Algorithm()
}

func textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}

func splitMessageIntoLines(msg string) [][]byte {
	rows := strings.Split(msg, "\n")

	msgs := make([][]byte, 0, len(rows))

	for _, row := range rows {
		if strings.TrimSpace(row) == "" {
			continue
		}

		msgs = append(msgs, []byte(row))
	}

	return msgs
}
