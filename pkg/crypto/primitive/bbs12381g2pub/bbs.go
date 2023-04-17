/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package bbs12381g2pub contains BBS+ signing primitives and keys. Although it can be used directly, it is recommended
// to use BBS+ keys created by the kms along with the framework's Crypto service.
// The default local Crypto service is found at: "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
//
//	while the remote Crypto service is found at: "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
package bbs12381g2pub

import (
	bbs "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

// BBSG2Pub defines BBS+ signature scheme where public key is a point in the field of G2.
// BBS+ signature scheme (as defined in https://eprint.iacr.org/2016/663.pdf, section 4.3).
type BBSG2Pub = bbs.BBSG2Pub

// New creates a new BBSG2Pub.
func New() *BBSG2Pub {
	return bbs.New()
}

// ProofNonce is a nonce for Proof of Knowledge proof.
type ProofNonce = bbs.ProofNonce

// ParseProofNonce creates a new ProofNonce from bytes.
func ParseProofNonce(proofNonceBytes []byte) *ProofNonce {
	return bbs.ParseProofNonce(proofNonceBytes)
}
