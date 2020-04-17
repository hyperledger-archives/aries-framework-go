/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"github.com/google/tink/go/tink"
)

// EncrypterHelper is a helper for Content Encryption of composite ECDH-ES key wrapping + AEAD content encryption
type EncrypterHelper interface {
	// GetSymmetricKeySize gives the size of the Encryption key (CEK) in bytes
	GetSymmetricKeySize() int

	// GetAEAD returns the newly created AEAD primitive used for the content Encryption
	GetAEAD(symmetricKeyValue []byte) (tink.AEAD, error)

	// GetTagSize provides the aead primitive tag size
	GetTagSize() int

	// GetIVSize provides the aead primitive nonce size
	GetIVSize() int
}
