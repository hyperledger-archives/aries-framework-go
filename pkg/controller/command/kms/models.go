/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

// CreateKeySetResponse for returning key pair
type CreateKeySetResponse struct {
	//  encryption public key base58 encoded
	EncryptionPublicKey string `json:"encryptionPublicKey,omitempty"`
	//  signature public key base58 encoded
	SignaturePublicKey string `json:"signaturePublicKey,omitempty"`
}
