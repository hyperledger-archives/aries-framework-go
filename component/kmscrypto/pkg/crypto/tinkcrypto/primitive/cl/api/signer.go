//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

// Signer is the signing interface primitive for CL Anoncreds used by Tink.
type Signer interface {
	GetCorrectnessProof() ([]byte, error)
	Sign(
		values map[string]interface{},
		secrets []byte,
		correctnessProof []byte,
		nonces [][]byte,
		did string,
	) ([]byte, []byte, error)
	Free() error
}
