/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cl

// CredentialDefinition contains public data of CL CredDef.
type CredentialDefinition struct {
	CredPubKey              []byte
	CredDefCorrectnessProof []byte
	Attrs                   []string
}

// CredentialOffer contains nonce of CL CredOffer.
type CredentialOffer struct {
	Nonce []byte
}

// CredentialRequest contains nonce, proverID and blinded secrets of CL CredRequest.
type CredentialRequest struct {
	BlindedCredentialSecrets *BlindedCredentialSecrets
	Nonce                    []byte
	ProverID                 string
}

// BlindedCredentialSecrets contains handle, blinding factor and correctness proof of CL BlindedSecrets.
type BlindedCredentialSecrets struct {
	Handle           []byte
	BlindingFactor   []byte
	CorrectnessProof []byte
}

// Credential contains CL Credential's signature, correctness proof for it and related credential's values.
type Credential struct {
	Signature []byte
	Values    map[string]interface{}
	SigProof  []byte
}

// PresentationRequest contains items used for CL Proof generation.
type PresentationRequest struct {
	Items []*PresentationRequestItem
	Nonce []byte
}

// PresentationRequestItem consists of revealed attributes and predicates upon which CL Proof is generated.
type PresentationRequestItem struct {
	RevealedAttrs []string
	Predicates    []*Predicate
}

// Predicate defines predicate for CL Proof.
type Predicate struct {
	Attr  string
	PType string
	Value int32
}

// Proof wraps CL Proof in raw bytes.
type Proof struct {
	Proof []byte
}
