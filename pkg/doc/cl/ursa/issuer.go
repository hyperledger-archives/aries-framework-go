//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ursa

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cl"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// Issuer is an ursa implementation of the CL Issuer API.
type Issuer struct {
	crypto crypto.Crypto
	kh     interface{}
	pubKey []byte
	attrs  []string
}

// NewIssuer insaniates a service for the provided keyID and attributes.
func NewIssuer(provider cl.Provider, keyID string, attrs []string) (*Issuer, error) {
	km := provider.KMS()

	kh, err := km.Get(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get KeyHandle for %s: %w", keyID, err)
	}

	pubKey, kt, err := km.ExportPubKeyBytes(keyID)
	if err != nil {
		return nil, err
	}

	if kt != kms.CLCredDefType {
		return nil, errors.New("not a CredDef key")
	}

	return &Issuer{kh: kh, crypto: provider.Crypto(), pubKey: pubKey, attrs: attrs}, nil
}

// GetCredentialDefinition returns a public CredDef data - public key, correctness proof and attributes
// returns:
// 		credDef as *CredentialDefinition
//		error in case of errors
func (s *Issuer) GetCredentialDefinition() (*cl.CredentialDefinition, error) {
	correctnessProof, err := s.crypto.GetCorrectnessProof(s.kh)
	if err != nil {
		return nil, err
	}

	return &cl.CredentialDefinition{CredDefCorrectnessProof: correctnessProof, CredPubKey: s.pubKey, Attrs: s.attrs}, nil
}

// OfferCredential generates CredOffer containing valid nonce
// returns:
// 		offer as *CredentialOffer
//		error in case of errors
func (s *Issuer) OfferCredential() (*cl.CredentialOffer, error) {
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}

	return &cl.CredentialOffer{Nonce: nonce}, nil
}

// IssueCredential issues and signs Credential for values and CredRequest
// provided by prover and CredOffer from the previous step
// Resulting Credential will contain signature and signature's correctness proof, along with issued attributes
// returns:
// 		credential as *Credential
//		error in case of errors
func (s *Issuer) IssueCredential(
	values map[string]interface{},
	credRequest *cl.CredentialRequest,
	credOffer *cl.CredentialOffer,
) (*cl.Credential, error) {
	sig, sigProof, err := s.crypto.SignWithSecrets(
		s.kh,
		values,
		credRequest.BlindedCredentialSecrets.Handle,
		credRequest.BlindedCredentialSecrets.CorrectnessProof,
		[][]byte{credOffer.Nonce, credRequest.Nonce},
		credRequest.ProverID,
	)
	if err != nil {
		return nil, err
	}

	return &cl.Credential{Signature: sig, SigProof: sigProof, Values: values}, nil
}
