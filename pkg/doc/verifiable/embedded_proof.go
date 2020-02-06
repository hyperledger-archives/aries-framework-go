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

type embeddedProofType int

const (
	linkedDataProof embeddedProofType = iota
)

// nolint:gochecknoglobals
var proofTypesMapping = map[string]embeddedProofType{
	"Ed25519Signature2018": linkedDataProof,
}

func parseEmbeddedProof(proofMap map[string]interface{}) (embeddedProofType, error) {
	proofType, ok := proofMap["type"]
	if !ok {
		return -1, errors.New("proof type is missing")
	}

	embeddedProofType, ok := proofTypesMapping[safeStringValue(proofType)]
	if !ok {
		return -1, fmt.Errorf("unsupported proof type: %s", proofType)
	}

	return embeddedProofType, nil
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
		return nil, errors.New("check embedded proof: expecting [string]interface{}, got something else")
	}

	proofType, err := parseEmbeddedProof(proofMap)
	if err != nil {
		return nil, err
	}

	switch proofType {
	case linkedDataProof:
		err = checkLinkedDataProof(docBytes, vcOpts.ldpSuite, vcOpts.publicKeyFetcher)
	default:
		err = fmt.Errorf("unsupported proof type: %v", proofType)
	}

	if err != nil {
		return nil, fmt.Errorf("check embedded proof: %w", err)
	}

	return docBytes, nil
}
