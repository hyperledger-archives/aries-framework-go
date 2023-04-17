//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"fmt"

	"github.com/google/tink/go/keyset"

	bld "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/blinder"
	sgn "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/signer"
)

// Blind will blind provided values with MasterSecret provided in a kh
// returns:
//
//	blinded values in []byte
//	error in case of errors
func (t *Crypto) Blind(kh interface{}, values ...map[string]interface{}) ([][]byte, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, errBadKeyHandleFormat
	}

	blinder, err := bld.NewBlinder(keyHandle)
	if err != nil {
		return nil, fmt.Errorf("create new CL blinder: %w", err)
	}

	defer blinder.Free() // nolint: errcheck

	if len(values) == 0 {
		blinded, err := blinder.Blind(map[string]interface{}{})
		if err != nil {
			return nil, err
		}

		return [][]byte{blinded}, nil
	}

	var blindeds [][]byte

	if len(values) == 0 {
		values = []map[string]interface{}{}
	}

	for _, val := range values {
		blinded, err := blinder.Blind(val)
		if err != nil {
			return nil, err
		}

		blindeds = append(blindeds, blinded)
	}

	return blindeds, nil
}

// GetCorrectnessProof will return correctness proof for a public key handle
// returns:
//
//	correctness proof in []byte
//	error in case of errors
func (t *Crypto) GetCorrectnessProof(kh interface{}) ([]byte, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, errBadKeyHandleFormat
	}

	signer, err := sgn.NewSigner(keyHandle)
	if err != nil {
		return nil, fmt.Errorf("create new CL signer: %w", err)
	}

	defer signer.Free() // nolint: errcheck

	correctnessProof, err := signer.GetCorrectnessProof()
	if err != nil {
		return nil, err
	}

	return correctnessProof, nil
}

// SignWithSecrets will generate a signature and related correctness proof
// for the provided values using secrets and related DID
// returns:
//
//	signature in []byte
//	correctness proof in []byte
//	error in case of errors
func (t *Crypto) SignWithSecrets(kh interface{}, values map[string]interface{},
	secrets []byte, correctnessProof []byte, nonces [][]byte, did string) ([]byte, []byte, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, nil, errBadKeyHandleFormat
	}

	signer, err := sgn.NewSigner(keyHandle)
	if err != nil {
		return nil, nil, fmt.Errorf("create new CL signer: %w", err)
	}

	defer signer.Free() // nolint: errcheck

	signature, signatureCorrectnessProof, err := signer.Sign(values, secrets, correctnessProof, nonces, did)
	if err != nil {
		return nil, nil, err
	}

	return signature, signatureCorrectnessProof, nil
}
