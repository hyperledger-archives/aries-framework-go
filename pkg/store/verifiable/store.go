/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	nameSpace = "verifiable"
)

// ErrNotFound signals that the entry for the given DID and key is not present in the store.
var ErrNotFound = errors.New("did not found under given key")

// Store stores vc
type Store struct {
	store storage.Store
}

type provider interface {
	StorageProvider() storage.Provider
}

// New returns a new vc store
func New(ctx provider) (*Store, error) {
	store, err := ctx.StorageProvider().OpenStore(nameSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to open vc store: %w", err)
	}

	return &Store{store: store}, nil
}

// SaveVC save verifiable credential
func (s *Store) SaveVC(vc *verifiable.Credential) error {
	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal vc: %w", err)
	}

	if err := s.store.Put(vc.ID, vcBytes); err != nil {
		return fmt.Errorf("failed to put vc: %w", err)
	}

	return nil
}

// GetVC get verifiable credential
func (s *Store) GetVC(vcID string) (*verifiable.Credential, error) {
	vcBytes, err := s.store.Get(vcID)
	if err != nil {
		return nil, fmt.Errorf("failed to get vc: %w", err)
	}

	vc, _, err := verifiable.NewCredential(vcBytes)
	if err != nil {
		return nil, fmt.Errorf("new credential failed: %w", err)
	}

	return vc, nil
}
