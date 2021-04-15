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
type emptyRes struct{}

// emptyResponse model
//
// swagger:response emptyResponse
type emptyResponse struct { // nolint:unused,deadcode
	// in: body
	Body emptyRes
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

// savePresentationReq model
//
// This is used to save the verifiable presentation.
//
// swagger:parameters savePresentationReq
type savePresentationReq struct { // nolint: unused,deadcode
	// Params for saving the verifiable presentation
	//
	// in: body
	Params verifiable.PresentationExt
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
type credentialRes struct {

	// in: body
	verifiable.Credential
}

// getPresentationReq model
//
// This is used to retrieve the verifiable presentation.
//
// swagger:parameters getPresentationReq
type getPresentationReq struct { // nolint: unused,deadcode
	// VP ID - pass base64 version of the ID
	// in: path
	// required: true
	ID string `json:"id"`
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

// removeCredentialByNameReq model
//
// This is used to remove the verifiable credential by name.
//
// swagger:parameters removeCredentialByNameReq
type removeCredentialByNameReq struct { // nolint: unused,deadcode
	// VC Name
	//
	// in: path
	// required: true
	Name string `json:"name"`
}

// removePresentationByNameReq model
//
// This is used to remove the verifiable presentation by name.
//
// swagger:parameters removePresentationByNameReq
type removePresentationByNameReq struct { // nolint: unused,deadcode
	// VC Name
	//
	// in: path
	// required: true
	Name string `json:"name"`
}

// credentialRecord model
//
// This is used to return credential record.
//
// swagger:response credentialRecord
type credentialRecord struct {
	// in: body
	verifiablestore.Record
}

// credentialRecordResult model
//
// This is used to return credential records.
//
// swagger:response credentialRecordResult
type credentialRecordResult struct {
	// in: body
	Result []*verifiablestore.Record `json:"result,omitempty"`
}

// presentationRecordResult model
//
// This is used to return presentation records.
//
// swagger:response presentationRecordResult
type presentationRecordResult struct {
	// in: body
	Result []*verifiablestore.Record `json:"result,omitempty"`
}

// generatePresentationReq model
//
// This is used to generate the verifiable presentation.
//
// swagger:parameters generatePresentationReq
type generatePresentationReq struct { // nolint: unused,deadcode
	// Params for generating the verifiable presentation (pass the vc document as a raw JSON)
	//
	// in: body
	Params verifiable.PresentationRequest
}

// generatePresentationByIDReq model
//
// This is used to generate the verifiable presentation by id.
//
// swagger:parameters generatePresentationByIDReq
type generatePresentationByIDReq struct { // nolint: unused,deadcode
	// Params for generating the verifiable presentation by id (pass the vc document as a raw JSON)
	//
	// in: body
	Params verifiable.PresentationRequestByID
}

// presentationRes model
//
// This is used for returning the verifiable presentation
//
// swagger:response presentationRes
type presentationRes struct {

	// in: body
	VerifiablePresentation json.RawMessage `json:"verifiablePresentation,omitempty"`
}

// signCredentialReq model
//
// This is used to sign a credential.
//
// swagger:parameters signCredentialReq
type signCredentialReq struct { // nolint: unused,deadcode
	// Params for signing a credential
	//
	// in: body
	Params verifiable.SignCredentialRequest
}

// signCredentialRes model
//
// This is used for returning the sign credential response
//
// swagger:response signCredentialRes
type signCredentialRes struct {

	// in: body
	VerifiableCredential json.RawMessage `json:"verifiableCredential,omitempty"`
}

// deriveCredentialReq model
//
// This is used for deriving a credential.
//
// swagger:parameters deriveCredentialReq
type deriveCredentialReq struct { // nolint: unused,deadcode
	// Params for deriving a credential
	//
	// in: body
	Params verifiable.DeriveCredentialRequest
}

// deriveCredentialRes model
//
// This is used for returning the derive credential response.
//
// swagger:response deriveCredentialRes
type deriveCredentialRes struct {

	// in: body
	verifiable.Credential
}
