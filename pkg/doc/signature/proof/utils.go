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

// GetProofs gets proof(s) from LD Object
func GetProofs(jsonLdObject map[string]interface{}) ([]*Proof, error) {
	entry, ok := jsonLdObject[jsonldProof]
	if !ok {
		return nil, ErrProofNotFound
	}

	typedEntry, ok := entry.([]interface{})
	if !ok {
		return nil, errors.New("expecting []interface{}, got something else")
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

// AddProof adds a proof to LD Object
func AddProof(jsonLdObject map[string]interface{}, proof *Proof) error {
	var proofs []interface{}
	entry, exists := jsonLdObject[jsonldProof]
	if exists {
		var ok bool
		proofs, ok = entry.([]interface{})
		if !ok {
			return errors.New("expecting []interface{}, got something else")
		}
	}

	proofs = append(proofs, proof.JSONLdObject())
	jsonLdObject[jsonldProof] = proofs

	return nil
}

// GetCopyWithoutProof gets copy of JSON LD Object without proofs (signatures)
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

// ErrProofNotFound is returned when proof is not found
var ErrProofNotFound = errors.New("proof not found")
