/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// MockDIDCreator mock implementation of DID creator
// to be used only for unit tests
type MockDIDCreator struct {
	Failure error
	Doc     *did.Doc
}

// CreateDID mock implementation of create DID
func (m *MockDIDCreator) CreateDID(opts ...wallet.DocOpts) (*did.Doc, error) {
	if m.Failure != nil {
		return nil, m.Failure
	}

	return m.Doc, nil
}
