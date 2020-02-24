/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
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
	Params verifiable.Credential
}
