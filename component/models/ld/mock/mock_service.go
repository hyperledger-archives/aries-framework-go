/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mock

import (
	"github.com/hyperledger/aries-framework-go/component/models/ld/context"
	"github.com/hyperledger/aries-framework-go/component/models/ld/context/remote"
	"github.com/hyperledger/aries-framework-go/component/models/ld/store"
)

// Service is a mock JSON-LD service.
type Service struct {
	ProviderID                   string
	RemoteProviderRecords        []store.RemoteProviderRecord
	ErrAddContexts               error
	ErrAddRemoteProvider         error
	ErrRefreshRemoteProvider     error
	ErrDeleteRemoteProvider      error
	ErrGetAllRemoteProviders     error
	ErrRefreshAllRemoteProviders error
}

// AddContexts adds JSON-LD contexts to the underlying storage.
func (s *Service) AddContexts(documents []context.Document) error {
	if s.ErrAddContexts != nil {
		return s.ErrAddContexts
	}

	return nil
}

// AddRemoteProvider adds remote provider and JSON-LD contexts from that provider.
func (s *Service) AddRemoteProvider(providerEndpoint string, opts ...remote.ProviderOpt) (string, error) {
	if s.ErrAddRemoteProvider != nil {
		return "", s.ErrAddRemoteProvider
	}

	return s.ProviderID, nil
}

// RefreshRemoteProvider updates contexts from the remote provider.
func (s *Service) RefreshRemoteProvider(providerID string, opts ...remote.ProviderOpt) error {
	if s.ErrRefreshRemoteProvider != nil {
		return s.ErrRefreshRemoteProvider
	}

	return nil
}

// DeleteRemoteProvider deletes remote provider and contexts from that provider.
func (s *Service) DeleteRemoteProvider(providerID string, opts ...remote.ProviderOpt) error {
	if s.ErrDeleteRemoteProvider != nil {
		return s.ErrDeleteRemoteProvider
	}

	return nil
}

// GetAllRemoteProviders gets all remote providers.
func (s *Service) GetAllRemoteProviders() ([]store.RemoteProviderRecord, error) {
	if s.ErrGetAllRemoteProviders != nil {
		return nil, s.ErrGetAllRemoteProviders
	}

	return s.RemoteProviderRecords, nil
}

// RefreshAllRemoteProviders updates contexts from all remote providers.
func (s *Service) RefreshAllRemoteProviders(opts ...remote.ProviderOpt) error {
	if s.ErrRefreshAllRemoteProviders != nil {
		return s.ErrRefreshAllRemoteProviders
	}

	return s.ErrRefreshAllRemoteProviders
}
