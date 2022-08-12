/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cl

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// Issuer contains all high-level methods to process CL Anoncreds on the issuer's side.
type Issuer interface {
	// GetCredentialDefinition returns a public CredDef data - public key, correctness proof and attributes
	// returns:
	// 		credDef as *CredentialDefinition
	//		error in case of errors
	GetCredentialDefinition() (*CredentialDefinition, error)
	// OfferCredential generates CredOffer containing valid nonce
	// returns:
	// 		offer as *CredentialOffer
	//		error in case of errors
	OfferCredential() (*CredentialOffer, error)
	// IssueCredential issues and signs Credential for values and CredRequest
	// provided by prover and CredOffer from the previous step
	// Resulting Credential will contain signature and signature's correctness proof, along with issued attributes
	// returns:
	// 		credential as *Credential
	//		error in case of errors
	IssueCredential(values map[string]interface{},
		credentialRequest *CredentialRequest, credOffer *CredentialOffer) (*Credential, error)
}

// Prover contains all high-level methods to process CL Anoncreds on the prover's side.
type Prover interface {
	// RequestCredential generates CredRequest which contains blinded secrets with MS, using issuer's CredDef public data
	// and CredOffer from the previous step
	// returns:
	// 		request as *CredentialRequest
	//		error in case of errors
	RequestCredential(credOffer *CredentialOffer,
		credDef *CredentialDefinition, proverID string) (*CredentialRequest, error)
	// ProcessCredential updates issued Credential signature for CredDef, using blinding factor from a CredRequest
	// returns:
	// 		credential as *Credential
	//		error in case of errors
	ProcessCredential(credential *Credential, credRequest *CredentialRequest,
		credDef *CredentialDefinition) (*Credential, error)
	// CreateProof composes Proof for the provided Credentials for CredDefs
	// matching revealead attrs and predicates specified in PresentationRequest
	// returns:
	// 		proof as *Proof
	//		error in case of errors
	CreateProof(presentationRequest *PresentationRequest, credentials []*Credential,
		credDefs []*CredentialDefinition) (*Proof, error)
}

// Verifier contains all high-level methods to process CL Anoncreds on the verifier's side.
type Verifier interface {
	// RequestPresentation generates PresentationRequest with unique nonce and provided list of attrs and predicates
	// returns:
	// 		request as *PresentationRequest
	//		error in case of errors
	RequestPresentation(items []*PresentationRequestItem) (*PresentationRequest, error)
	// VerifyProof verifies given Proof according to PresentationRequest and CredDefs
	// returns:
	//		error in case of errors or nil if proof verification was successful
	VerifyProof(proof *Proof, presentationRequest *PresentationRequest, credDefs []*CredentialDefinition) error
}

// Provider for CL services constructors.
type Provider interface {
	KMS() kms.KeyManager
	Crypto() crypto.Crypto
}
