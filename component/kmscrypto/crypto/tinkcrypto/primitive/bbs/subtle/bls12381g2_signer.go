/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

// BLS12381G2Signer is the BBS+ signer for BLS12-381 curve for keys on a G2 group.
// Currently this is the only available BBS+ signer in aries-framework-go (see `pkg/doc/bbs/bbs12381g2pub/bbs.go`).
// Other BBS+ signers can be added later if needed.
type BLS12381G2Signer struct {
	privateKeyBytes []byte
	bbsPrimitive    *bbs12381g2pub.BBSG2Pub
}

// NewBLS12381G2Signer creates a new instance of BLS12381G2Signer with the provided privateKey.
func NewBLS12381G2Signer(privateKey []byte) *BLS12381G2Signer {
	return &BLS12381G2Signer{
		privateKeyBytes: privateKey,
		bbsPrimitive:    bbs12381g2pub.New(),
	}
}

// Sign will sign create signature of each message and aggregate it into a single signature using the signer's
// private key.
// returns:
// 		signature in []byte
//		error in case of errors
func (s *BLS12381G2Signer) Sign(messages [][]byte) ([]byte, error) {
	return s.bbsPrimitive.Sign(messages, s.privateKeyBytes)
}
