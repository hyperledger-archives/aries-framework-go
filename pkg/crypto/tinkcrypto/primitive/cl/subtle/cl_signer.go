//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/subtle"
)

// CLSigner is used for CL signature using the provided CredDef key.
type CLSigner = subtle.CLSigner

// NewCLSigner creates a new instance of CLSigner with the provided privateKey.
func NewCLSigner(privKey, pubKey, correctnessProof []byte, attrs []string) (*CLSigner, error) {
	return subtle.NewCLSigner(privKey, pubKey, correctnessProof, attrs)
}
