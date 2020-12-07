/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignatureproof2020

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/bbs/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
)

const (
	securityContext = "https://w3id.org/security/v2"
	proofField      = "proofValue"
)

// SelectiveDisclosure creates selective disclosure from the input doc which must have a BBS+ proof
// (with BbsBlsSignature2020 type).
func (s *Suite) SelectiveDisclosure(doc map[string]interface{}, revealDoc map[string]interface{},
	pubKeyBytes, nonce []byte, opts ...jsonld.ProcessorOpts) (map[string]interface{}, error) {
	docCompacted, err := getCompactedWithSecuritySchema(doc, opts...)
	if err != nil {
		return nil, err
	}

	rawProofs := docCompacted["proof"]
	if rawProofs == nil {
		return nil, errors.New("document does not have a proof")
	}

	delete(docCompacted, "proof")

	proofInfo, err := getBlsProof(rawProofs)
	if err != nil {
		return nil, err
	}

	blsProof := proofInfo.blsProof

	proofValue := blsProof[proofField].(string) //nolint:errcheck

	signatureBytes, err := decodeBase64(proofValue)
	if err != nil {
		return nil, fmt.Errorf("invalid %s format: %w", proofField, err)
	}

	verData, err := buildVerificationData(docCompacted, blsProof, revealDoc, opts...)
	if err != nil {
		return nil, err
	}

	bls := bbs12381g2pub.New()

	signatureProofBytes, err := bls.DeriveProof(verData.blsMessages, signatureBytes,
		nonce, pubKeyBytes, verData.revealIndexes)
	if err != nil {
		return nil, fmt.Errorf("derive BBS+ proof: %w", err)
	}

	derivedProof := map[string]interface{}{
		"type":               signatureType,
		"nonce":              base64.StdEncoding.EncodeToString(nonce),
		"verificationMethod": blsProof["verificationMethod"],
		"proofPurpose":       blsProof["proofPurpose"],
		"created":            blsProof["created"],
		proofField:           base64.StdEncoding.EncodeToString(signatureProofBytes),
	}

	allProofs := insertProof(proofInfo.allProofs, proofInfo.blsProofInd, derivedProof)
	verData.revealDocumentResult["proof"] = allProofs

	return verData.revealDocumentResult, nil
}

type blsProofInfo struct {
	blsProof    map[string]interface{}
	allProofs   []map[string]interface{}
	blsProofInd int
}

func getBlsProof(rawProofs interface{}) (*blsProofInfo, error) {
	allProofs, err := getProofs(rawProofs)
	if err != nil {
		return nil, err
	}

	blsProofInd := -1

	var blsProof map[string]interface{}

	for i, proof := range allProofs {
		if proof["type"] == "https://w3c-ccg.github.io/ldp-bbs2020/context/v1#BbsBlsSignature2020" {
			blsProofInd = i
			allProofs = deleteProof(allProofs, i)
			blsProof = proof
			blsProof["@context"] = securityContext
		}
	}

	if blsProofInd == -1 {
		return nil, errors.New("no BbsBlsSignature2020 proof present")
	}

	return &blsProofInfo{
		blsProof:    blsProof,
		allProofs:   allProofs,
		blsProofInd: blsProofInd,
	}, nil
}

type verificationData struct {
	blsMessages          [][]byte
	revealIndexes        []int
	revealDocumentResult map[string]interface{}
}

func buildVerificationData(docCompacted, blsProof, revealDoc map[string]interface{},
	opts ...jsonld.ProcessorOpts) (*verificationData, error) {
	documentStatements, err := createVerifyDocumentData(docCompacted, opts...)
	if err != nil {
		return nil, err
	}

	proofStatements, err := createVerifyProofData(blsProof, opts...)
	if err != nil {
		return nil, err
	}

	transformedInputDocumentStatements := make([]string, len(documentStatements))

	for i, element := range documentStatements {
		// todo this can be simplified by just check of prefix _:c14n
		nodeIdentifier := strings.Split(element, " ")[0]
		if strings.HasPrefix(nodeIdentifier, "_:c14n") {
			transformedInputDocumentStatements[i] = "urn:bnid:" + nodeIdentifier
			continue
		}

		transformedInputDocumentStatements[i] = element
	}

	revealDocumentResult, err := jsonld.Default().Frame(documentStatements, revealDoc, opts...)
	if err != nil {
		return nil, err
	}

	revealDocumentStatements, err := createVerifyDocumentData(revealDocumentResult, opts...)
	if err != nil {
		return nil, err
	}

	numberOfProofStatements := len(proofStatements)
	revealIndexes := make([]int, numberOfProofStatements+len(revealDocumentStatements))

	for i := 0; i < numberOfProofStatements; i++ {
		revealIndexes[i] = i
	}

	transformedInputDocumentStatementsMap := make(map[string]int)
	for i, statement := range transformedInputDocumentStatements {
		transformedInputDocumentStatementsMap[statement] = i
	}

	for i := range revealDocumentStatements {
		statement := revealDocumentStatements[i]
		statementInd := transformedInputDocumentStatementsMap[statement]
		revealIndexes[i+numberOfProofStatements] = numberOfProofStatements + statementInd
	}

	allInputStatements := append(proofStatements, documentStatements...)
	blsMessages := toArrayOfBytes(allInputStatements)

	return &verificationData{
		blsMessages:          blsMessages,
		revealIndexes:        revealIndexes,
		revealDocumentResult: revealDocumentResult,
	}, nil
}

func getCompactedWithSecuritySchema(docMap map[string]interface{},
	opts ...jsonld.ProcessorOpts) (map[string]interface{}, error) {
	contextMap := map[string]interface{}{
		"@context": securityContext,
	}

	return jsonld.Default().Compact(docMap, contextMap, opts...)
}

func getProofs(appProofs interface{}) ([]map[string]interface{}, error) {
	switch p := appProofs.(type) {
	case map[string]interface{}:
		return []map[string]interface{}{p}, nil
	case []interface{}:
		proofs := make([]map[string]interface{}, len(p))

		for i := range p {
			pp, ok := p[i].(map[string]interface{})
			if !ok {
				return nil, errors.New("proof is not a JSON map")
			}

			proofs[i] = pp
		}

		return proofs, nil
	default:
		return nil, errors.New("proof is not map or array of maps")
	}
}

func createVerifyDocumentData(doc map[string]interface{}, opts ...jsonld.ProcessorOpts) ([]string, error) {
	docBytes, err := jsonld.Default().GetCanonicalDocument(doc, opts...)
	if err != nil {
		return nil, err
	}

	return splitMessageIntoLines(string(docBytes)), nil
}

func splitMessageIntoLines(msg string) []string {
	rows := strings.Split(msg, "\n")

	msgs := make([]string, 0, len(rows))

	for i := range rows {
		if strings.TrimSpace(rows[i]) != "" {
			msgs = append(msgs, rows[i])
		}
	}

	return msgs
}

func createVerifyProofData(proof map[string]interface{}, opts ...jsonld.ProcessorOpts) ([]string, error) {
	delete(proof, proofField)

	proofBytes, err := jsonld.Default().GetCanonicalDocument(proof, opts...)
	if err != nil {
		return nil, err
	}

	return splitMessageIntoLines(string(proofBytes)), nil
}

func toArrayOfBytes(messages []string) [][]byte {
	res := make([][]byte, len(messages))

	for i := range messages {
		res[i] = []byte(messages[i])
	}

	return res
}

func insertProof(proofs []map[string]interface{}, index int, proof map[string]interface{}) []map[string]interface{} {
	if len(proofs) == index {
		return append(proofs, proof)
	}

	proofs = append(proofs[:index+1], proofs[index:]...) // index < len(a)
	proofs[index] = proof

	return proofs
}

func deleteProof(proofs []map[string]interface{}, index int) []map[string]interface{} {
	return append(proofs[:index], proofs[index+1:]...)
}

func decodeBase64(s string) ([]byte, error) {
	allEncodings := []*base64.Encoding{
		base64.RawURLEncoding, base64.StdEncoding,
	}

	for _, encoding := range allEncodings {
		value, err := encoding.DecodeString(s)
		if err == nil {
			return value, nil
		}
	}

	return nil, errors.New("unsupported encoding")
}
