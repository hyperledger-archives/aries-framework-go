/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didstore

import (
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didstore"
)

// MockDidMethod is mock did method
type MockDidMethod struct {
	PutErr      error
	GetValue    *diddoc.Doc
	GetErr      error
	AcceptValue bool
}

// Put did document
func (r *MockDidMethod) Put(doc *diddoc.Doc, by *[]didstore.ModifiedBy) error {
	return r.PutErr
}

// Get did document
func (r *MockDidMethod) Get(id string) (*diddoc.Doc, error) {
	return r.GetValue, r.GetErr
}

// Accept did method
func (r *MockDidMethod) Accept(method string) bool {
	return r.AcceptValue
}
