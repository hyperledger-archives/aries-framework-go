/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package doc have public key
//
package doc

import gojose "github.com/square/go-jose/v3"

// PublicKey struct.
type PublicKey struct {
	ID       string
	Type     string
	Purposes []string
	JWK      gojose.JSONWebKey
}

// ModifiedBy key/signature used to update the DID Document.
type ModifiedBy struct {
	Key string `json:"key,omitempty"`
	Sig string `json:"sig,omitempty"`
}
