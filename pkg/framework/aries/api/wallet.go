/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
)

// CloseableKMS interface
type CloseableKMS interface {
	io.Closer
	legacykms.KeyManager
	legacykms.Signer
}

// KMSCreator method to create new key management service
type KMSCreator func(provider Provider) (CloseableKMS, error)
