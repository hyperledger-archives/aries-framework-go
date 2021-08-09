/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	"github.com/hyperledger/aries-framework-go/pkg/store/ld"
)

// MockService is a mock JSON-LD service.
type MockService struct {
	ProviderID                   string
	RemoteProviderRecords        []ld.RemoteProviderRecord
	ErrAddContexts               error
	ErrAddRemoteProvider         error
	ErrRefreshRemoteProvider     error
	ErrDeleteRemoteProvider      error
	ErrGetAllRemoteProviders     error
	ErrRefreshAllRemoteProviders error
}

// AddContexts adds JSON-LD contexts to the underlying storage.
func (m *MockService) AddContexts(documents []ldcontext.Document) error {
	if m.ErrAddContexts != nil {
		return m.ErrAddContexts
	}

	return nil
}

// AddRemoteProvider adds remote provider and JSON-LD contexts from that provider.
func (m *MockService) AddRemoteProvider(providerEndpoint string, opts ...remote.ProviderOpt) (string, error) {
	if m.ErrAddRemoteProvider != nil {
		return "", m.ErrAddRemoteProvider
	}

	return m.ProviderID, nil
}

// RefreshRemoteProvider updates contexts from the remote provider.
func (m *MockService) RefreshRemoteProvider(providerID string, opts ...remote.ProviderOpt) error {
	if m.ErrRefreshRemoteProvider != nil {
		return m.ErrRefreshRemoteProvider
	}

	return nil
}

// DeleteRemoteProvider deletes remote provider and contexts from that provider.
func (m *MockService) DeleteRemoteProvider(providerID string, opts ...remote.ProviderOpt) error {
	if m.ErrDeleteRemoteProvider != nil {
		return m.ErrDeleteRemoteProvider
	}

	return nil
}

// GetAllRemoteProviders gets all remote providers.
func (m *MockService) GetAllRemoteProviders() ([]ld.RemoteProviderRecord, error) {
	if m.ErrGetAllRemoteProviders != nil {
		return nil, m.ErrGetAllRemoteProviders
	}

	return m.RemoteProviderRecords, nil
}

// RefreshAllRemoteProviders updates contexts from all remote providers.
func (m *MockService) RefreshAllRemoteProviders(opts ...remote.ProviderOpt) error {
	if m.ErrRefreshAllRemoteProviders != nil {
		return m.ErrRefreshAllRemoteProviders
	}

	return m.ErrRefreshAllRemoteProviders
}
