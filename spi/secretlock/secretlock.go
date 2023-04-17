/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package secretlock provides the API for secret lock services, used to secure keys used by Aries KMS implementations.
package secretlock

// Service provides crypto service used internally by the KMS
// it is responsible for wrapping/unwrapping keys stored by the KMS using a master key.
type Service interface {
	// Encrypt req for master key in keyURI
	Encrypt(keyURI string, req *EncryptRequest) (*EncryptResponse, error)
	// Decrypt req for master key in keyURI
	Decrypt(keyURI string, req *DecryptRequest) (*DecryptResponse, error)
}

// EncryptRequest for encrypting remote kms requests.
type EncryptRequest struct {
	Plaintext                   string
	AdditionalAuthenticatedData string
}

// DecryptRequest for decrypting remote kms requests.
type DecryptRequest struct {
	Ciphertext                  string
	AdditionalAuthenticatedData string
}

// EncryptResponse for receiving encryption response from remote kms requests.
type EncryptResponse struct {
	Ciphertext string
}

// DecryptResponse for receiving decryption response from remote kms requests.
type DecryptResponse struct {
	Plaintext string
}
