//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ursa

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/cl"
)

// Verifier is an ursa implementation of the CL Verifier API.
type Verifier struct{}

// NewVerifier insaniates Verifier service.
func NewVerifier() (*Verifier, error) {
	return &Verifier{}, nil
}

// RequestPresentation generates PresentationRequest with unique nonce and provided list of attrs and predicates
// returns:
// 		request as *PresentationRequest
//		error in case of errors
func (s *Verifier) RequestPresentation(items []*cl.PresentationRequestItem) (*cl.PresentationRequest, error) {
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}

	return &cl.PresentationRequest{Items: items, Nonce: nonce}, nil
}

// VerifyProof verifies given Proof according to PresentationRequest and CredDefs
// returns:
//		error in case of errors or nil if proof verification was successful
func (s *Verifier) VerifyProof(proof *cl.Proof,
	presentationRequest *cl.PresentationRequest,
	credDefs []*cl.CredentialDefinition,
) error {
	if len(presentationRequest.Items) != len(credDefs) {
		return fmt.Errorf("not enough credential definitions provided to fulfill the presentsation request")
	}

	var subProofItems []*subProofItem

	for i, item := range presentationRequest.Items {
		subProofItem := &subProofItem{
			CredentialDefinition: credDefs[i],
			Item:                 item,
		}

		subProofItems = append(subProofItems, subProofItem)
	}

	err := verifyProof(proof, subProofItems, presentationRequest.Nonce)

	return err
}
