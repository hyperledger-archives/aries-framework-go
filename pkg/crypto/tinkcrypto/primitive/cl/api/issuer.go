//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/


package api

// Issuer is the signing interface primitive for CL signatures used by Tink.
type Issuer interface {
	GetCredentialDefinition() (*CredentialDefinition, error)
	CreateCredentialOffer() (*CredentialOffer, error)
	IssueCredential(values map[string]interface{}, credentialRequest *CredentialRequest, credOffer *CredentialOffer) (*Credential, error)
	Free() error
}
