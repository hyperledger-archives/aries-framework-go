/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/bbs"

	bbsapi "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/bbs/api"
)

// NewSigner returns a BBS Signer primitive from the given keyset handle.
func NewSigner(h *keyset.Handle) (bbsapi.Signer, error) {
	return bbs.NewSigner(h)
}

// NewSignerWithKeyManager returns a BBS Signer primitive from the given keyset handle and custom key manager.
func NewSignerWithKeyManager(h *keyset.Handle, km registry.KeyManager) (bbsapi.Signer, error) {
	return bbs.NewSignerWithKeyManager(h, km)
}
