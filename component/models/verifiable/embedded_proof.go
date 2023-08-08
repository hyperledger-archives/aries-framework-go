/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/models"
	jsonld "github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/bbsblssignatureproof2020"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/ecdsasecp256k1signature2019"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/ed25519signature2020"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

const (
	ed25519Signature2018        = "Ed25519Signature2018"
	ed25519Signature2020        = "Ed25519Signature2020"
	jsonWebSignature2020        = "JsonWebSignature2020"
	ecdsaSecp256k1Signature2019 = "EcdsaSecp256k1Signature2019"
	bbsBlsSignature2020         = "BbsBlsSignature2020"
	bbsBlsSignatureProof2020    = "BbsBlsSignatureProof2020"
)

func getProofType(proofMap map[string]interface{}) (string, error) {
	proofType, ok := proofMap["type"]
	if !ok {
		return "", errors.New("proof type is missing")
	}

	proofTypeStr := safeStringValue(proofType)
	switch proofTypeStr {
	case ed25519Signature2018, jsonWebSignature2020, ecdsaSecp256k1Signature2019,
		bbsBlsSignature2020, bbsBlsSignatureProof2020, ed25519Signature2020:
		return proofTypeStr, nil
	default:
		return "", fmt.Errorf("unsupported proof type: %s", proofType)
	}
}

type embeddedProofCheckOpts struct {
	publicKeyFetcher   PublicKeyFetcher
	disabledProofCheck bool

	ldpSuites []verifier.SignatureSuite

	dataIntegrityOpts *verifyDataIntegrityOpts

	jsonldCredentialOpts
}

func checkEmbeddedProof(docBytes []byte, opts *embeddedProofCheckOpts) error { // nolint:gocyclo
	if opts.disabledProofCheck {
		return nil
	}

	var jsonldDoc map[string]interface{}

	if err := json.Unmarshal(docBytes, &jsonldDoc); err != nil {
		return fmt.Errorf("embedded proof is not JSON: %w", err)
	}

	delete(jsonldDoc, "jwt")

	proofElement, ok := jsonldDoc["proof"]
	if !ok || proofElement == nil {
		// do not make a check if there is no proof defined as proof presence is not mandatory
		return nil
	}

	proofs, err := getProofs(proofElement)
	if err != nil {
		return fmt.Errorf("check embedded proof: %w", err)
	}

	if len(opts.externalContext) > 0 {
		// Use external contexts for check of the linked data proofs to enrich JSON-LD context vocabulary.
		jsonldDoc["@context"] = jsonld.AppendExternalContexts(jsonldDoc["@context"], opts.externalContext...)
	}

	if len(proofs) > 0 {
		typeStr, ok := proofs[0]["type"]
		if ok && typeStr == models.DataIntegrityProof {
			docBytes, err = json.Marshal(jsonldDoc)
			if err != nil {
				return err
			}

			return checkDataIntegrityProof(docBytes, opts.dataIntegrityOpts)
		}
	}

	ldpSuites, err := getSuites(proofs, opts)
	if err != nil {
		return err
	}

	if opts.publicKeyFetcher == nil {
		return errors.New("public key fetcher is not defined")
	}

	err = checkLinkedDataProof(jsonldDoc, ldpSuites, opts.publicKeyFetcher, &opts.jsonldCredentialOpts)
	if err != nil {
		return fmt.Errorf("check embedded proof: %w", err)
	}

	return nil
}

// nolint:gocyclo
func getSuites(proofs []map[string]interface{}, opts *embeddedProofCheckOpts) ([]verifier.SignatureSuite, error) {
	ldpSuites := opts.ldpSuites

	for i := range proofs {
		t, err := getProofType(proofs[i])
		if err != nil {
			return nil, fmt.Errorf("check embedded proof: %w", err)
		}

		if len(opts.ldpSuites) == 0 {
			switch t {
			case ed25519Signature2018:
				ldpSuites = append(ldpSuites, ed25519signature2018.New(
					suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier())))
			case ed25519Signature2020:
				ldpSuites = append(ldpSuites, ed25519signature2020.New(
					suite.WithVerifier(ed25519signature2020.NewPublicKeyVerifier())))
			case jsonWebSignature2020:
				ldpSuites = append(ldpSuites, jsonwebsignature2020.New(
					suite.WithVerifier(jsonwebsignature2020.NewPublicKeyVerifier())))
			case ecdsaSecp256k1Signature2019:
				ldpSuites = append(ldpSuites, ecdsasecp256k1signature2019.New(
					suite.WithVerifier(ecdsasecp256k1signature2019.NewPublicKeyVerifier())))
			case bbsBlsSignature2020:
				ldpSuites = append(ldpSuites, bbsblssignature2020.New(
					suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier())))
			case bbsBlsSignatureProof2020:
				nonce, err := getNonce(proofs[i])
				if err != nil {
					return nil, err
				}

				ldpSuites = append(ldpSuites, bbsblssignatureproof2020.New(
					suite.WithVerifier(bbsblssignatureproof2020.NewG2PublicKeyVerifier(nonce))))
			}
		}
	}

	return ldpSuites, nil
}

func getNonce(proof map[string]interface{}) ([]byte, error) {
	if nonce, ok := proof["nonce"]; ok {
		n, err := base64.StdEncoding.DecodeString(nonce.(string))
		if err != nil {
			return nil, err
		}

		return n, nil
	}

	return []byte{}, nil
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
