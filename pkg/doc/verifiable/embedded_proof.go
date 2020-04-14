/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
)

func mustBeLinkedDataProof(proofMap map[string]interface{}) error {
	proofType, ok := proofMap["type"]
	if !ok {
		return errors.New("proof type is missing")
	}

	proofTypeStr := safeStringValue(proofType)
	switch proofTypeStr {
	case "Ed25519Signature2018", "JsonWebSignature2020", "EcdsaSecp256k1Signature2019":
		return nil
	default:
		return fmt.Errorf("unsupported proof type: %s", proofType)
	}
}

func checkEmbeddedProof(docBytes []byte, vcOpts *credentialOpts) ([]byte, error) {
	if vcOpts.disabledProofCheck {
		return docBytes, nil
	}

	var jsonldDoc map[string]interface{}

	err := json.Unmarshal(docBytes, &jsonldDoc)
	if err != nil {
		return nil, fmt.Errorf("embedded proof is not JSON: %w", err)
	}

	proofElement, ok := jsonldDoc["proof"]
	if !ok || proofElement == nil {
		// do not make a check if there is no proof defined as proof presence is not mandatory
		return docBytes, nil
	}

	proofMap, ok := proofElement.(map[string]interface{})
	if !ok {
		return nil, errors.New("check embedded proof: expecting [string]interface{}")
	}

	err = mustBeLinkedDataProof(proofMap)
	if err != nil {
		return nil, err
	}

	if vcOpts.publicKeyFetcher == nil {
		return nil, errors.New("public key fetcher is not defined")
	}

	err = checkLinkedDataProof(docBytes, vcOpts.ldpSuites, vcOpts.publicKeyFetcher)
	if err != nil {
		return nil, fmt.Errorf("check embedded proof: %w", err)
	}

	return docBytes, nil
}
