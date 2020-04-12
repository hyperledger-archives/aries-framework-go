/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	verifiablestore "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
)

// validateCredentialReq model
//
// This is used to validate the verifiable credential.
//
// swagger:parameters validateCredentialReq
type validateCredentialReq struct { // nolint: unused,deadcode
	// Params for validating the verifiable credential (pass the vc document as a string)
	//
	// in: body
	Params verifiable.Credential
}

// emptyRes model
//
// swagger:response emptyRes
type emptyRes struct {
}

// saveCredentialReq model
//
// This is used to save the verifiable credential.
//
// swagger:parameters saveCredentialReq
type saveCredentialReq struct { // nolint: unused,deadcode
	// Params for saving the verifiable credential (pass the vc document as a string)
	//
	// in: body
	Params verifiable.CredentialExt
}

// getCredentialReq model
//
// This is used to retrieve the verifiable credential.
//
// swagger:parameters getCredentialReq
type getCredentialReq struct { // nolint: unused,deadcode
	// VC ID - pass base64 version of the ID
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// credentialRes model
//
// This is used for returning query connection result for single record search
//
// swagger:response credentialRes
type credentialRes struct { // nolint: unused,deadcode

	// in: body
	verifiable.Credential
}

// getCredentialByNameReq model
//
// This is used to retrieve the verifiable credential by name.
//
// swagger:parameters getCredentialByNameReq
type getCredentialByNameReq struct { // nolint: unused,deadcode
	// VC Name
	//
	// in: path
	// required: true
	Name string `json:"name"`
}

// PresentationRequest is model for verifiable credential.
type PresentationRequest struct {
	VerifiableCredential string          `json:"verifiableCredential,omitempty"`
	DidDoc               json.RawMessage `json:"doc,omitempty"`
}

// credentialRecord model
//
// This is used to return credential record.
//
// swagger:response credentialRecord
type credentialRecord struct {
	// in: body
	verifiablestore.CredentialRecord
}

// credentialRecordResult model
//
// This is used to return credential records.
//
// swagger:response credentialRecordResult
type credentialRecordResult struct {
	// in: body
	Result []*verifiablestore.CredentialRecord `json:"result,omitempty"`
}

// generatePresentationReq model
//
// This is used to generate the verifiable presentation.
//
// swagger:parameters generatePresentationReq
type generatePresentationReq struct { // nolint: unused,deadcode
	// Params for generating the verifiable presentation (pass the vc document as a string)
	//
	// in: body
	Params verifiable.Credential
}

// presentationByIDReq model
//
// This is used to generate the verifiable presentation from stored verifiable credential.
//
// swagger:parameters presentationByIDReq
type presentationByIDReq struct { // nolint: unused,deadcode
	// VC ID - pass base64 version of the ID
	//
	// in: path
	// required: true
	ID string `json:"id"`

	// DID
	DID string `json:"did"`
}

// presentationRes model
//
// This is used for returning the verifiable presentation
//
// swagger:response presentationRes
type presentationRes struct {

	// in: body
	verifiable.Presentation
}
