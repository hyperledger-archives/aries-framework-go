/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
)

type signer struct {
	kms   legacykms.Signer
	keyID string
}

func newSigner(kms legacykms.Signer, keyID string) *signer {
	return &signer{kms: kms, keyID: keyID}
}

func (s *signer) Sign(data []byte) ([]byte, error) {
	return s.kms.SignMessage(data, s.keyID)
}
