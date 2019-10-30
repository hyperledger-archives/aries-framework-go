/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// CloseableKMS interface
type CloseableKMS interface {
	io.Closer
	kms.KeyManager
	kms.Signer
}

// KMSCreator method to create new key management service
type KMSCreator func(provider Provider) (CloseableKMS, error)
