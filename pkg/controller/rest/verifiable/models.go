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
// This is used validate the verifiable credential.
//
// swagger:parameters validateCredentialReq
type validateCredentialReq struct { // nolint: unused,deadcode
	// Params for validating the verifiable credential (pass the vc document as a string)
	//
	// in: body
	Params verifiable.Credential
}

// validateCredentialRes model
//
// swagger:response validateCredentialRes
type validateCredentialRes struct { // nolint: unused,deadcode
}
