/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didstore

import (
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// MockDidStore is mock did store
type MockDidStore struct {
	PutErr   error
	GetValue *diddoc.Doc
	GetErr   error
}

// Put did document
func (r *MockDidStore) Put(doc *diddoc.Doc) error {
	return r.PutErr
}

// Get did document
func (r *MockDidStore) Get(id string) (*diddoc.Doc, error) {
	return r.GetValue, r.GetErr
}
