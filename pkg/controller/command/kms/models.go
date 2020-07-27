/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

// CreateKeySetRequest is model for createKeySey request.
type CreateKeySetRequest struct {
	KeyType string `json:"keyType,omitempty"`
}

// CreateKeySetResponse for returning key pair.
type CreateKeySetResponse struct {
	//  key id base64 encoded
	KeyID string `json:"keyID,omitempty"`
	//  public key base64 encoded
	PublicKey string `json:"publicKey,omitempty"`
}

// JSONWebKey contains subset of json web key json properties.
type JSONWebKey struct {
	Use string `json:"use,omitempty"`
	Kty string `json:"kty,omitempty"`
	Kid string `json:"kid,omitempty"`
	Crv string `json:"crv,omitempty"`
	Alg string `json:"alg,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
}
