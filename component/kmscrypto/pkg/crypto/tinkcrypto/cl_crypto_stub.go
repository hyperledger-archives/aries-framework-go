//go:build !ursa
// +build !ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"errors"
)

// Blind will blind provided values with MasterSecret provided in a kh
// returns:
// 		blinded values in []byte
//		error in case of errors
// STUB.
func (t *Crypto) Blind(kh interface{}, values ...map[string]interface{}) ([][]byte, error) {
	return nil, errors.New("not implemented")
}

// GetCorrectnessProof will return correctness proof for a public key handle
// returns:
// 		correctness proof in []byte
//		error in case of errors
// STUB.
func (t *Crypto) GetCorrectnessProof(kh interface{}) ([]byte, error) {
	return nil, errors.New("not implemented")
}

// SignWithSecrets will generate a signature and related correctness proof
// for the provided values using secrets and related DID
// returns:
// 		signature in []byte
// 		correctness proof in []byte
//		error in case of errors
// STUB.
func (t *Crypto) SignWithSecrets(kh interface{}, values map[string]interface{},
	secrets []byte, correctnessProof []byte, nonces [][]byte, did string) ([]byte, []byte, error) {
	return nil, nil, errors.New("not implemented")
}
