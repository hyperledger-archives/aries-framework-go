/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	"github.com/xeipuuv/gojsonschema"
)

// jwtDecoding defines if to decode VC from JWT
type jwtDecoding int

const (
	// noJwtDecoding not a JWT
	noJwtDecoding jwtDecoding = iota

	// jwsDecoding indicated to unmarshal from Signed Token
	jwsDecoding

	// unsecuredJWTDecoding indicates to unmarshal from Unsecured Token
	unsecuredJWTDecoding
)

// Proof defines embedded proof of Verifiable Credential
type Proof interface{}

type typedID struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`
}

// RefreshService provides a way to automatic refresh of expired Verifiable Credential
type RefreshService typedID

// TermsOfUse represents terms of use of Verifiable Credential by Issuer or Verifiable Presentation by Holder.
type TermsOfUse typedID

func describeSchemaValidationError(result *gojsonschema.Result, what string) string {
	errMsg := what + " is not valid:\n"
	for _, desc := range result.Errors() {
		errMsg += fmt.Sprintf("- %s\n", desc)
	}
	return errMsg
}
