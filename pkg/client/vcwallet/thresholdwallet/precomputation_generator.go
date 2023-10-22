package thresholdwallet

import "hash"

type PrecomputationsGenerator interface {
	// GeneratePrecomputation generate the precomputations for each party
	// and returns the public key and precomputations for each party as a Document.
	GeneratePrecomputation(h func() hash.Hash, seed []byte, t, n, k int) (*Document, []*Document, error)
	
	// NextMsgIndex returns the next to be used presignature index.
	// Returns an error if there are no presignatures left.
	NextMsgIndex() (int, error)
}
