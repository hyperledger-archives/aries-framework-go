//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ursa

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cl"
)

// Prover is an ursa implementation of the CL Prover API.
type Prover struct {
	crypto crypto.Crypto
	kh     interface{}
}

// NewProver insaniates a Prover service for the provided keyID.
func NewProver(provider cl.Provider, keyID string) (*Prover, error) {
	km := provider.KMS()

	kh, err := km.Get(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get KeyHandle for %s: %w", keyID, err)
	}

	return &Prover{kh: kh, crypto: provider.Crypto()}, nil
}

// RequestCredential generates CredRequest which contains blinded secrets with MS, using issuer's CredDef public data
// and CredOffer from the previous step
// returns:
// 		request as *CredentialRequest
//		error in case of errors
func (s *Prover) RequestCredential(
	credOffer *cl.CredentialOffer,
	credDef *cl.CredentialDefinition,
	proverID string,
) (*cl.CredentialRequest, error) {
	blindedMs, err := s.crypto.Blind(s.kh)
	if err != nil {
		return nil, err
	}

	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}

	secrets, err := blindCredentialSecrets(
		credDef.CredPubKey,
		credDef.CredDefCorrectnessProof,
		credOffer.Nonce,
		blindedMs[0],
	)
	if err != nil {
		return nil, err
	}

	return &cl.CredentialRequest{BlindedCredentialSecrets: secrets, Nonce: nonce, ProverID: proverID}, nil
}

// ProcessCredential updates issued Credential signature for CredDef, using blinding factor from a CredRequest
// returns:
// 		credential as *Credential
//		error in case of errors
func (s *Prover) ProcessCredential(
	credential *cl.Credential,
	credRequest *cl.CredentialRequest,
	credDef *cl.CredentialDefinition,
) error {
	blindedVals, err := s.crypto.Blind(s.kh, credential.Values)
	if err != nil {
		return err
	}

	err = processCredentialSignature(
		credential,
		credRequest,
		credDef,
		blindedVals[0],
	)

	return err
}

// CreateProof composes Proof for the provided Credentials for CredDefs
// matching revealead attrs and predicates specified in PresentationRequest
// returns:
// 		proof as *Proof
//		error in case of errors
func (s *Prover) CreateProof(
	presentationRequest *cl.PresentationRequest,
	credentials []*cl.Credential,
	credDefs []*cl.CredentialDefinition,
) (*cl.Proof, error) {
	if len(presentationRequest.Items) != len(credentials) {
		return nil, fmt.Errorf("not enough credentials provided to fulfill the presentsation request")
	}

	if len(presentationRequest.Items) != len(credDefs) {
		return nil, fmt.Errorf("not enough credential definitions provided to fulfill the presentsation request")
	}

	var multivals []map[string]interface{}
	for _, cred := range credentials {
		multivals = append(multivals, cred.Values)
	}

	blindedMultiVals, err := s.crypto.Blind(s.kh, multivals...)
	if err != nil {
		return nil, err
	}

	var subProofItems []*subProofItem

	for i, item := range presentationRequest.Items {
		subProofItem := &subProofItem{
			BlindedVals:          blindedMultiVals[i],
			Credential:           credentials[i],
			CredentialDefinition: credDefs[i],
			Item:                 item,
		}

		subProofItems = append(subProofItems, subProofItem)
	}

	proof, err := createProof(subProofItems, presentationRequest.Nonce)
	if err != nil {
		return nil, err
	}

	return &cl.Proof{Proof: proof}, nil
}
