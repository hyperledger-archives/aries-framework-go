/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	"github.com/hyperledger/aries-framework-go/pkg/store/ld"
)

// provider contains dependencies for the JSON-LD service.
type provider interface {
	JSONLDContextStore() ld.ContextStore
	JSONLDRemoteProviderStore() ld.RemoteProviderStore
}

// Service is a service that supports JSON-LD operations.
type Service interface {
	AddContexts(documents []ldcontext.Document) error
	AddRemoteProvider(providerEndpoint string, opts ...remote.ProviderOpt) (string, error)
	RefreshRemoteProvider(providerID string, opts ...remote.ProviderOpt) error
	DeleteRemoteProvider(providerID string, opts ...remote.ProviderOpt) error
	GetAllRemoteProviders() ([]ld.RemoteProviderRecord, error)
	RefreshAllRemoteProviders(opts ...remote.ProviderOpt) error
}

// DefaultService is a default implementation of Service.
type DefaultService struct {
	contextStore        ld.ContextStore
	remoteProviderStore ld.RemoteProviderStore
}

// New returns a new default JSON-LD service instance.
func New(ctx provider) *DefaultService {
	return &DefaultService{
		contextStore:        ctx.JSONLDContextStore(),
		remoteProviderStore: ctx.JSONLDRemoteProviderStore(),
	}
}

// AddContexts adds JSON-LD contexts to the underlying storage.
func (s *DefaultService) AddContexts(documents []ldcontext.Document) error {
	if err := s.contextStore.Import(documents); err != nil {
		return fmt.Errorf("add contexts: %w", err)
	}

	return nil
}

// AddRemoteProvider adds remote provider and JSON-LD contexts from that provider.
func (s *DefaultService) AddRemoteProvider(providerEndpoint string, opts ...remote.ProviderOpt) (string, error) {
	p := remote.NewProvider(providerEndpoint, opts...)

	contexts, err := p.Contexts()
	if err != nil {
		return "", fmt.Errorf("get contexts from remote provider: %w", err)
	}

	record, err := s.remoteProviderStore.Save(providerEndpoint)
	if err != nil {
		return "", fmt.Errorf("save remote provider: %w", err)
	}

	if err := s.contextStore.Import(contexts); err != nil {
		return "", fmt.Errorf("import contexts: %w", err)
	}

	return record.ID, nil
}

// RefreshRemoteProvider updates contexts from the remote provider.
func (s *DefaultService) RefreshRemoteProvider(providerID string, opts ...remote.ProviderOpt) error {
	record, err := s.remoteProviderStore.Get(providerID)
	if err != nil {
		return fmt.Errorf("get remote provider from store: %w", err)
	}

	p := remote.NewProvider(record.Endpoint, opts...)

	contexts, err := p.Contexts()
	if err != nil {
		return fmt.Errorf("get contexts from remote provider: %w", err)
	}

	if err := s.contextStore.Import(contexts); err != nil {
		return fmt.Errorf("import contexts: %w", err)
	}

	return nil
}

// DeleteRemoteProvider deletes remote provider and contexts from that provider.
func (s *DefaultService) DeleteRemoteProvider(providerID string, opts ...remote.ProviderOpt) error {
	record, err := s.remoteProviderStore.Get(providerID)
	if err != nil {
		return fmt.Errorf("get remote provider from store: %w", err)
	}

	p := remote.NewProvider(record.Endpoint, opts...)

	contexts, err := p.Contexts()
	if err != nil {
		return fmt.Errorf("get contexts from remote provider: %w", err)
	}

	if err := s.contextStore.Delete(contexts); err != nil {
		return fmt.Errorf("delete contexts: %w", err)
	}

	if err := s.remoteProviderStore.Delete(record.ID); err != nil {
		return fmt.Errorf("delete remote provider record: %w", err)
	}

	return nil
}

// GetAllRemoteProviders gets all remote providers.
func (s *DefaultService) GetAllRemoteProviders() ([]ld.RemoteProviderRecord, error) {
	records, err := s.remoteProviderStore.GetAll()
	if err != nil {
		return nil, fmt.Errorf("get remote provider records: %w", err)
	}

	return records, nil
}

// RefreshAllRemoteProviders updates contexts from all remote providers.
func (s *DefaultService) RefreshAllRemoteProviders(opts ...remote.ProviderOpt) error {
	records, err := s.remoteProviderStore.GetAll()
	if err != nil {
		return fmt.Errorf("get remote provider records: %w", err)
	}

	for _, record := range records {
		p := remote.NewProvider(record.Endpoint, opts...)

		contexts, err := p.Contexts()
		if err != nil {
			return fmt.Errorf("get contexts from remote provider: %w", err)
		}

		if err := s.contextStore.Import(contexts); err != nil {
			return fmt.Errorf("import contexts: %w", err)
		}
	}

	return nil
}
