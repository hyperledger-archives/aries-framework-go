/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

// Credential is model for verifiable credential.
type Credential struct {
	VC string `json:"vc,omitempty"`
}

// CredentialExt is model for verifiable credential with fields related to command features.
type CredentialExt struct {
	Credential
	Name string `json:"name,omitempty"`
}

// IDArg model
//
// This is used for querying/removing by ID from input json.
//
type IDArg struct {
	// Connection ID
	ID string `json:"id"`
}
