/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignatureproof2020"
)

// GenerateBBSSelectiveDisclosure generate BBS+ selective disclosure from one BBS+ signature.
func (vc *Credential) GenerateBBSSelectiveDisclosure(revealDoc map[string]interface{},
	pubKeyBytes, nonce []byte, opts ...jsonld.ProcessorOpts) (*Credential, error) {
	if vc.Proofs == nil || len(vc.Proofs) != 1 {
		return nil, errors.New("expected one proof present")
	}

	proof := vc.Proofs[0]
	if proof["type"] != "BbsBlsSignature2020" {
		return nil, errors.New("expected BbsBlsSignature2020 proof")
	}

	suite := bbsblssignatureproof2020.New()

	vcDoc, err := toMap(vc)
	if err != nil {
		return nil, err
	}

	vcWithSelectiveDisclosureDoc, err := suite.SelectiveDisclosure(vcDoc, revealDoc, pubKeyBytes, nonce, opts...)
	if err != nil {
		return nil, fmt.Errorf("create VC selective disclosure: %w", err)
	}

	vcWithSelectiveDisclosureBytes, err := json.Marshal(vcWithSelectiveDisclosureDoc)
	if err != nil {
		return nil, err
	}

	return ParseUnverifiedCredential(vcWithSelectiveDisclosureBytes)
}
