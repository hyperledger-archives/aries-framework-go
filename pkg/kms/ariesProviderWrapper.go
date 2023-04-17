/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// AriesWrapperStoreName is the store name used when creating a KMS store using kms.NewAriesProviderWrapper.
const AriesWrapperStoreName = kms.AriesWrapperStoreName

// NewAriesProviderWrapper returns an implementation of the kms.Store interface that wraps an
// Aries provider implementation, allowing it to be used with a KMS.
func NewAriesProviderWrapper(provider storage.Provider) (Store, error) {
	return kms.NewAriesProviderWrapper(provider)
}
