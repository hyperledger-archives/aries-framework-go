/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package secretlock

// EncryptRequest for encrypting remote kms requests
type EncryptRequest struct {
	Plaintext                   string
	AdditionalAuthenticatedData string
}

// DecryptRequest for decrypting remote kms requests
type DecryptRequest struct {
	Ciphertext                  string
	AdditionalAuthenticatedData string
}

// EncryptResponse for receiving encryption response from remote kms requests
type EncryptResponse struct {
	Ciphertext string
}

// DecryptResponse for receiving decryption response from remote kms requests
type DecryptResponse struct {
	Plaintext string
}
