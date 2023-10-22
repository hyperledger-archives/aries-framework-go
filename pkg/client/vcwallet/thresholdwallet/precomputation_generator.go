package thresholdwallet

import "hash"

type PrecomputationsGenerator interface {
	GeneratePrecomputation(h func() hash.Hash, seed []byte, t, n, k int) (*Document, []*Document, error)
	NextMsgIndex() (int, error)
}
