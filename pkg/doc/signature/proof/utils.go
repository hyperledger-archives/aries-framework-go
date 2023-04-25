/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"errors"
)

const (
	jsonldProof = "proof"
)

// GetProofs gets proof(s) from LD Object.
func GetProofs(jsonLdObject map[string]interface{}) ([]*Proof, error) {
	entry, ok := jsonLdObject[jsonldProof]
	if !ok {
		return nil, ErrProofNotFound
	}

	var typedEntry []interface{}
	switch te := entry.(type) {
	case []interface{}:
		typedEntry = te
	case map[string]interface{}:
		typedEntry = []interface{}{te}
	default:
		return nil, errors.New("expecting []interface{} or map[string]interface{}, got something else")
	}

	var result []*Proof

	for _, e := range typedEntry {
		emap, ok := e.(map[string]interface{})
		if !ok {
			return nil, errors.New("wrong interface, expecting []interface{}")
		}

		proof, err := NewProof(emap)
		if err != nil {
			return nil, err
		}

		result = append(result, proof)
	}

	return result, nil
}

// AddProof adds a proof to LD Object.
func AddProof(jsonLdObject map[string]interface{}, proof *Proof) error {
	var proofs []interface{}

	entry, exists := jsonLdObject[jsonldProof]

	if exists {
		switch p := entry.(type) {
		case []interface{}:
			proofs = p
		default:
			proofs = []interface{}{p}
		}
	}

	proofs = append(proofs, proof.JSONLdObject())
	jsonLdObject[jsonldProof] = proofs

	return nil
}

// GetCopyWithoutProof gets copy of JSON LD Object without proofs (signatures).
func GetCopyWithoutProof(jsonLdObject map[string]interface{}) map[string]interface{} {
	if jsonLdObject == nil {
		return nil
	}

	dest := make(map[string]interface{})

	for k, v := range jsonLdObject {
		if k != jsonldProof {
			dest[k] = v
		}
	}

	return dest
}

// ErrProofNotFound is returned when proof is not found.
var ErrProofNotFound = errors.New("proof not found")
