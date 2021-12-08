/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// QueryParams contains credential queries for querying credential from wallet.
// Refer https://w3c-ccg.github.io/vp-request-spec/#format for more details.
type QueryParams struct {
	// Type of the query.
	// Allowed values  'QueryByExample', 'QueryByFrame', 'PresentationExchange', 'DIDAuth'
	Type string `json:"type"`

	// Query can contain one or more credential queries.
	Query []json.RawMessage `json:"credentialQuery"`
}

// ProofOptions model
//
// Options for adding linked data proofs to a verifiable credential or a verifiable presentation.
// To be used as options for issue/prove wallet features.
//
type ProofOptions struct {
	// Controller is a DID to be for signing. This option is required for issue/prove wallet features.
	Controller string `json:"controller,omitempty"`
	// VerificationMethod is the URI of the verificationMethod used for the proof.
	// Optional, by default Controller public key matching 'assertion' for issue or 'authentication' for prove functions.
	VerificationMethod string `json:"verificationMethod,omitempty"`
	// Created date of the proof.
	// Optional, current system time will be used.
	Created *time.Time `json:"created,omitempty"`
	// Domain is operational domain of a digital proof.
	// Optional, by default domain will not be part of proof.
	Domain string `json:"domain,omitempty"`
	// Challenge is a random or pseudo-random value option authentication.
	// Optional, by default challenge will not be part of proof.
	Challenge string `json:"challenge,omitempty"`
	// ProofType is signature type used for signing.
	// Optional, by default proof will be generated in Ed25519Signature2018 format.
	ProofType string `json:"proofType,omitempty"`
	// ProofRepresentation is type of proof data expected, (Refer verifiable.SignatureProofValue)
	// Optional, by default proof will be represented as 'verifiable.SignatureProofValue'.
	ProofRepresentation *verifiable.SignatureRepresentation `json:"proofRepresentation,omitempty"`
}

// DeriveOptions model containing options for deriving a credential.
//
type DeriveOptions struct {
	// Frame is JSON-LD frame used for selective disclosure.
	Frame map[string]interface{} `json:"frame,omitempty"`
	// Nonce to prove uniqueness or freshness of the proof.
	Nonce string `json:"nonce,omitempty"`
}

// QueryByExampleDefinition is model for QueryByExample query type.
// https://w3c-ccg.github.io/vp-request-spec/#query-by-example
type QueryByExampleDefinition struct {
	Example *ExampleDefinition `json:"example"`
}

// QueryByFrameDefinition is model for QueryByExample query type.
// https://w3c-ccg.github.io/vp-request-spec/
// TODO QueryByExampleDefinition model is not yet finalized - https://github.com/w3c-ccg/vp-request-spec/issues/8
type QueryByFrameDefinition struct {
	Frame         map[string]interface{}    `json:"frame"`
	TrustedIssuer []TrustedIssuerDefinition `json:"trustedIssuer"`
}

// ExampleDefinition frame for QueryByExample.
// Refer - https://w3c-ccg.github.io/vp-request-spec/#example-2-a-query-by-example-query
// TODO currently `IssuerQuery` is ignored.
type ExampleDefinition struct {
	Context           []string                  `json:"@context"`
	Type              interface{}               `json:"type"`
	CredentialSubject map[string]string         `json:"credentialSubject"`
	CredentialSchema  map[string]string         `json:"credentialSchema"`
	TrustedIssuer     []TrustedIssuerDefinition `json:"trustedIssuer"`
	IssuerQuery       map[string]interface{}    `json:"issuerQuery"`
}

// TrustedIssuerDefinition is model for trusted issuer component in QueryByFrame & QueryByExample.
type TrustedIssuerDefinition struct {
	Issuer   string `json:"issuer"`
	Required bool   `json:"required"`
}

// KeyPair is response of creating key pair inside wallet.
type KeyPair struct {
	// base64 encoded key ID of the key created.
	KeyID string `json:"keyID,omitempty"`
	// base64 encoded public key of the key pair created.
	PublicKey string `json:"publicKey,omitempty"`
}

// CredentialInteractionStatus holds the status of credential share/issuance interaction from wallet.
// Typically holds web redirect info of credential interaction conclusion or problem-report.
type CredentialInteractionStatus struct {
	// One of the status present proof or issue credential interaction
	// Refer https://github.com/hyperledger/aries-rfcs/blob/main/features/0015-acks/README.md#ack-status.
	Status string `json:"status"`
	// Optional web redirect URL info sent by verifier.
	RedirectURL string `json:"url,omitempty"`
}
