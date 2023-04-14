/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

const (
	// Namespace is the store name used when creating a KMS store using kms.NewAriesProviderWrapper.
	// The reason this is here in addition to kms.AriesWrapperStoreName is because
	// the IndexedDB implementation refers to this. FOr the WASM unit tests, the aries-framework-go module import gets
	// replaced with the local version and so in order for both to work correctly, for now we have the constant defined
	// in both places.
	Namespace = localkms.Namespace
)

// package localkms is the default KMS service implementation of pkg/kms.KeyManager. It uses Tink keys to support the
// default Crypto implementation, pkg/crypto/tinkcrypto, and stores these keys in the format understood by Tink. It also
// uses a secretLock service to protect private key material in the storage.

// LocalKMS implements kms.KeyManager to provide key management capabilities using a local db.
// It uses an underlying secret lock service (default local secretLock) to wrap (encrypt) keys
// prior to storing them.
type LocalKMS = localkms.LocalKMS

// New will create a new (local) KMS service.
func New(primaryKeyURI string, p kms.Provider) (*LocalKMS, error) {
	return localkms.New(primaryKeyURI, p)
}
