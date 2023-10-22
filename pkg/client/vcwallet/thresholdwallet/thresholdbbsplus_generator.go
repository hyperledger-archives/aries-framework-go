package thresholdwallet

import (
	"errors"
	"fmt"
	"hash"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbsplusthresholdpub"
)

// ThresholdBBSGenetor implemented precomputation generator
// using the threshold bbs plus algorithm at /component/kmscrypto/primitive/bbsplusthresholdpub
type ThresholdBBSGenerator struct {
	nextMsgIndex int
	maxMsgIndex  int
}

// NewThresholdBBSPlusGenerator returns a new instance of Precomputation generator
// implementing the threshold bbs+ algorithm.
func NewThresholdBBSPlusGenerator() *ThresholdBBSGenerator {
	return &ThresholdBBSGenerator{
		nextMsgIndex: 0,
		maxMsgIndex:  0,
	}
}

func (tbg *ThresholdBBSGenerator) GeneratePrecomputation(h func() hash.Hash, seed []byte, t, n, k int) (string, *Document, []*Document, error) {
	pubKey, _, precomputations, err := bbsplusthresholdpub.GenerateKeyPair(h, seed, t, n, k)
	if err != nil {
		return "", nil, nil, err
	}
	collectionID := fmt.Sprintf(CollectionIDTemplate, uuid.New().URN())
	pubKeyByte, err := pubKey.Marshal()
	if err != nil {
		return "", nil, nil, err
	}

	publicKeyDoc := NewDocument(PublicKey, pubKeyByte, collectionID)
	precomputationDocs := make([]*Document, 0)
	for _, precomputation := range precomputations {
		precomputationByte, err := precomputation.ToBytes()
		if err != nil {
			return "", nil, nil, err
		}
		precomputationDoc := NewDocument(Precomputation, precomputationByte, collectionID)
		precomputationDocs = append(precomputationDocs, precomputationDoc)
	}

	tbg.nextMsgIndex = 0
	tbg.maxMsgIndex = k

	return collectionID, publicKeyDoc, precomputationDocs, nil
}

func (tbg *ThresholdBBSGenerator) NextMsgIndex() (int, error) {
	nextMsgIndex := tbg.nextMsgIndex
	if nextMsgIndex >= tbg.maxMsgIndex {
		return -1, errors.New("out of precomputations")
	}
	tbg.nextMsgIndex++
	return nextMsgIndex, nil
}
