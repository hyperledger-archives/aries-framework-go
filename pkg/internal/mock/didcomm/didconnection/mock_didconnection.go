/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didconnection

import (
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// MockDIDConnection mocks the did lookup store.
type MockDIDConnection struct {
	SaveRecordErr     error
	SaveConnectionErr error
	SaveKeysErr       error
	GetDIDValue       string
	GetDIDErr         error
	SaveDIDErr        error
	ResolveDIDErr     error
}

// SaveDID saves a DID to the store
func (m *MockDIDConnection) SaveDID(did string, keys ...string) error {
	return m.SaveRecordErr
}

// GetDID gets the DID stored under the given key
func (m *MockDIDConnection) GetDID(key string) (string, error) {
	return m.GetDIDValue, m.GetDIDErr
}

// SaveDIDConnection saves a DID connection
func (m *MockDIDConnection) SaveDIDConnection(myDID, theirDID string, theirKeys []string) error {
	return m.SaveConnectionErr
}

// SaveDIDByResolving saves a DID by resolving it then using its doc
func (m *MockDIDConnection) SaveDIDByResolving(did, serviceType, keyType string) error {
	return m.ResolveDIDErr
}

// SaveDIDFromDoc saves a DID using the given doc
func (m *MockDIDConnection) SaveDIDFromDoc(doc *diddoc.Doc, serviceType, keyType string) error {
	return m.SaveDIDErr
}
