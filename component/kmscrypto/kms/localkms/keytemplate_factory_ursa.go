//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/spi/kms"

	clbld "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/blinder"
	clsgn "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/signer"
)

// getKeyTemplate returns tink KeyTemplate associated with the provided keyType.
func getKeyTemplate(keyType kms.KeyType, opts ...kms.KeyOpts) (*tinkpb.KeyTemplate, error) {
	switch keyType {
	case kms.CLCredDefType:
		keyOpts := kms.NewKeyOpt()

		for _, opt := range opts {
			opt(keyOpts)
		}

		return clsgn.CredDefKeyTemplate(keyOpts.Attrs()), nil
	case kms.CLMasterSecretType:
		return clbld.MasterSecretKeyTemplate(), nil
	default:
		return keyTemplate(keyType, opts...)
	}
}
