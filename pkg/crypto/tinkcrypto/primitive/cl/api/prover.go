//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

// Prover interface primitive for CL signatures used by Tink.
type Prover interface {
	CreateCredentialRequest(credOffer *CredentialOffer, credDef *CredentialDefinition, proverId string) (*CredentialRequest, error)
	ProcessCredential(credential *Credential, credRequest *CredentialRequest, credDef *CredentialDefinition) error
	CreateProof(presentationRequest *PresentationRequest, credentials []*Credential, credDefs []*CredentialDefinition) (*Proof, error)
	Free() error
}
