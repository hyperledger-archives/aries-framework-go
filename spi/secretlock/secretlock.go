/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package secretlock provides the API for secret lock services, used to secure keys used by Aries KMS implementations.
package secretlock

import "github.com/trustbloc/kms-go/spi/secretlock"

// Service provides crypto service used internally by the KMS
// it is responsible for wrapping/unwrapping keys stored by the KMS using a master key.
type Service = secretlock.Service

// EncryptRequest for encrypting remote kms requests.
type EncryptRequest = secretlock.EncryptRequest

// DecryptRequest for decrypting remote kms requests.
type DecryptRequest = secretlock.DecryptRequest

// EncryptResponse for receiving encryption response from remote kms requests.
type EncryptResponse = secretlock.EncryptResponse

// DecryptResponse for receiving decryption response from remote kms requests.
type DecryptResponse = secretlock.DecryptResponse
