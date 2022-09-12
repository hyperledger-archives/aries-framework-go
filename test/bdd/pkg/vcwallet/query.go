/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	_ "embed" //nolint:gci // required for go:embed
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed testdata/query_by_example_fmt.json
var sampleQueryByExFmt string //nolint:gochecknoglobals

//go:embed testdata/presentation_definition_fmt.json
var presentationDefinitionFmt string //nolint:gochecknoglobals

//go:embed testdata/presentation_definition_v2.json
var presentationDefinitionFmtV2 string //nolint:gochecknoglobals

func (s *SDKSteps) getQuery(queryType, didID, format string) (json.RawMessage, error) {
	switch queryType {
	case "QueryByExample":
		return []byte(fmt.Sprintf(sampleQueryByExFmt, didID)), nil
	case "PresentationExchange":
		return []byte(fmt.Sprintf(presentationDefinitionFmt, didID)), nil
	case "PresentationExchange-v2":
		return []byte(pExV2Format(didID, s.crypto, format)), nil
	}

	// QueryByFrame is not covered in tests, since BBS isn't usable yet for JWT credentials
	return nil, fmt.Errorf("invalid queryType %v", queryType)
}

const (
	ecdsa = "ECDSA"
)

func pExV2Format(didID, crypto, format string) string {
	formatString := ""
	signingAlg := strings.Split(crypto, " ")[0]

	if format == "JWT" {
		alg := ""

		switch signingAlg {
		case "Ed25519":
			alg = "EdDSA"
		case ecdsa:
			alg = ecdsa
		}

		formatString = fmt.Sprintf(`{"jwt": {"alg":["%s"]}}`, alg)
	} else if format == "JSON-LD" {
		proofType := ""

		switch signingAlg {
		case "Ed25519":
			proofType = "Ed25519Signature2018"
		case ecdsa:
			proofType = "JSONWebSignature2020"
		}

		formatString = fmt.Sprintf(`{"ldp": {"proof_type":["%s"]}}`, proofType)
	}

	return fmt.Sprintf(presentationDefinitionFmtV2, didID, formatString)
}
