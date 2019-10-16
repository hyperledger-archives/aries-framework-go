/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didresolver

import (
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
)

// MockResolver is mock did resolver
type MockResolver struct {
}

// NewMockResolver return new instance of mock did resolver
func NewMockResolver() *MockResolver {
	return &MockResolver{}
}

// Resolve did document
func (r *MockResolver) Resolve(did string, opts ...didresolver.ResolveOpt) (*diddoc.Doc, error) {
	return nil, nil
}
