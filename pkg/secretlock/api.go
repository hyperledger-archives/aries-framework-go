/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package secretlock

// Package secretlock contains secret lock services to secure keys used by the Aries agent
// and more specifically used by the KMS service.

// Service provides crypto service used internally by the KMS
// it is responsible for wrapping/unwrapping keys stored by the KMS using a master key.
type Service interface {
	// Encrypt req for master key in keyURI
	Encrypt(keyURI string, req *EncryptRequest) (*EncryptResponse, error)
	// Decrypt req for master key in keyURI
	Decrypt(keyURI string, req *DecryptRequest) (*DecryptResponse, error)
}
