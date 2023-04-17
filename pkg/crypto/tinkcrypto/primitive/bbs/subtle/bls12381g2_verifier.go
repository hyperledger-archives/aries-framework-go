/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/bbs/subtle"
)

// BLS12381G2Verifier is the BBS+ signature/proof verifier for keys on BLS12-381 curve with a point in the G2 group.
// Currently this is the only available BBS+ verifier in aries-framework-go (see `pkg/doc/bbs/bbs12381g2pub/bbs.go`).
// Other BBS+ verifiers can be added later if needed.
type BLS12381G2Verifier = subtle.BLS12381G2Verifier

// NewBLS12381G2Verifier creates a new instance of BLS12381G2Verifier with the provided signerPublicKey.
func NewBLS12381G2Verifier(signerPublicKey []byte) *BLS12381G2Verifier {
	return subtle.NewBLS12381G2Verifier(signerPublicKey)
}
