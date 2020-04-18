/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ecdsasecp256k1signature2019"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
)

const (
	ed25519Signature2018        = "Ed25519Signature2018"
	jsonWebSignature2020        = "JsonWebSignature2020"
	ecdsaSecp256k1Signature2019 = "EcdsaSecp256k1Signature2019"
)

func getProofType(proofMap map[string]interface{}) (string, error) {
	proofType, ok := proofMap["type"]
	if !ok {
		return "", errors.New("proof type is missing")
	}

	proofTypeStr := safeStringValue(proofType)
	switch proofTypeStr {
	case ed25519Signature2018, jsonWebSignature2020, ecdsaSecp256k1Signature2019:
		return proofTypeStr, nil
	default:
		return "", fmt.Errorf("unsupported proof type: %s", proofType)
	}
}

func checkEmbeddedProof(docBytes []byte, vcOpts *credentialOpts) ([]byte, error) {
	if vcOpts.disabledProofCheck {
		return docBytes, nil
	}

	var jsonldDoc map[string]interface{}

	if err := json.Unmarshal(docBytes, &jsonldDoc); err != nil {
		return nil, fmt.Errorf("embedded proof is not JSON: %w", err)
	}

	proofElement, ok := jsonldDoc["proof"]
	if !ok || proofElement == nil {
		// do not make a check if there is no proof defined as proof presence is not mandatory
		return docBytes, nil
	}

	proofs, err := getProofs(proofElement)
	if err != nil {
		return nil, fmt.Errorf("check embedded proof: %w", err)
	}

	ldpSuites, err := getSuites(proofs, vcOpts)
	if err != nil {
		return nil, err
	}

	if vcOpts.publicKeyFetcher == nil {
		return nil, errors.New("public key fetcher is not defined")
	}

	err = checkLinkedDataProof(docBytes, ldpSuites, vcOpts.publicKeyFetcher)
	if err != nil {
		return nil, fmt.Errorf("check embedded proof: %w", err)
	}

	return docBytes, nil
}

func getSuites(proofs []map[string]interface{}, vcOpts *credentialOpts) ([]verifier.SignatureSuite, error) {
	ldpSuites := vcOpts.ldpSuites

	for i := range proofs {
		t, err := getProofType(proofs[i])
		if err != nil {
			return nil, fmt.Errorf("check embedded proof: %w", err)
		}

		if len(vcOpts.ldpSuites) == 0 {
			switch t {
			case ed25519Signature2018:
				ldpSuites = append(ldpSuites, ed25519signature2018.New(
					suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())))
			case jsonWebSignature2020:
				ldpSuites = append(ldpSuites, jsonwebsignature2020.New(
					suite.WithVerifier(jsonwebsignature2020.NewPublicKeyVerifier())))
			case ecdsaSecp256k1Signature2019:
				ldpSuites = append(ldpSuites, ecdsasecp256k1signature2019.New(
					suite.WithVerifier(ecdsasecp256k1signature2019.NewPublicKeyVerifier())))
			}
		}
	}

	return ldpSuites, nil
}

func getProofs(proofElement interface{}) ([]map[string]interface{}, error) {
	switch p := proofElement.(type) {
	case map[string]interface{}:
		return []map[string]interface{}{p}, nil

	case []interface{}:
		proofs := make([]map[string]interface{}, len(p))

		for i := range p {
			proofMap, ok := p[i].(map[string]interface{})
			if !ok {
				return nil, errors.New("invalid proof type")
			}

			proofs[i] = proofMap
		}

		return proofs, nil
	}

	return nil, errors.New("invalid proof type")
}
