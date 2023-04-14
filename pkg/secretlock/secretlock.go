/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package secretlock contains secret lock services to secure keys used by the Aries agent
// and more specifically used by the KMS service.
package secretlock

import (
	"github.com/hyperledger/aries-framework-go/spi/secretlock"
)

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
