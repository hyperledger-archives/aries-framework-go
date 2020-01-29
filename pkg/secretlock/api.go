/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secretlock

// package secretlock contains secrete lock services to secure keys used by the Aries agent
// and more specifically used by the KMS service.

// Service provides crypto service used internally by the KMS
type Service interface {
	// Encrypt req for master key in keyURI
	Encrypt(keyURI string, req *EncryptRequest) (*EncryptResponse, error)
	// Decrypt req for master key in keyURI
	Decrypt(keyURI string, req *DecryptRequest) (*DecryptResponse, error)
}
