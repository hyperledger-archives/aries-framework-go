/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

// CreateKeySetRequest is model for createKeySey request.
type CreateKeySetRequest struct {
	KeyType string `json:"keyType,omitempty"`
}

// CreateKeySetResponse for returning key pair
type CreateKeySetResponse struct {
	//  key id base64 encoded
	KeyID string `json:"keyID,omitempty"`
	//  public key base64 encoded
	PublicKey string `json:"publicKey,omitempty"`
}
