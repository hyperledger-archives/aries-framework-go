/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// NameSpace for did store.
	NameSpace = "didstore"

	didNameKey        = "didname_"
	didNameKeyPattern = didNameKey + "%s"
)

var logger = log.New("aries-framework/store/did")

// Store stores did doc.
type Store struct {
	store storage.Store
}

type provider interface {
	StorageProvider() storage.Provider
}

// New returns a new did store.
func New(ctx provider) (*Store, error) {
	store, err := ctx.StorageProvider().OpenStore(NameSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to open did store: %w", err)
	}

	err = ctx.StorageProvider().SetStoreConfig(NameSpace, storage.StoreConfiguration{TagNames: []string{didNameKey}})
	if err != nil {
		return nil, fmt.Errorf("failed to set store configuration: %w", err)
	}

	return &Store{store: store}, nil
}

// SaveDID saves a did doc.
func (s *Store) SaveDID(name string, didDoc *did.Doc) error {
	if name == "" {
		return errors.New("did name is mandatory")
	}

	id, err := s.GetDIDByName(name)
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return fmt.Errorf("get did using name : %w", err)
	}

	if id != "" {
		return errors.New("did name already exists")
	}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		return fmt.Errorf("failed to marshal didDoc: %w", err)
	}

	if err := s.store.Put(didDoc.ID, docBytes); err != nil {
		return fmt.Errorf("failed to put didDoc: %w", err)
	}

	if err := s.store.Put(didNameDataKey(name), []byte(didDoc.ID), storage.Tag{Name: didNameKey}); err != nil {
		return fmt.Errorf("store did name to id map : %w", err)
	}

	return nil
}

// GetDID retrieves a didDoc based on ID.
func (s *Store) GetDID(id string) (*did.Doc, error) {
	docBytes, err := s.store.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get did doc: %w", err)
	}

	didDoc, err := did.ParseDocument(docBytes)
	if err != nil {
		return nil, fmt.Errorf("umarshalling didDoc failed: %w", err)
	}

	return didDoc, nil
}

// GetDIDByName retrieves did id based on name.
func (s *Store) GetDIDByName(name string) (string, error) {
	idBytes, err := s.store.Get(didNameDataKey(name))
	if err != nil {
		return "", fmt.Errorf("fetch did doc id based on name : %w", err)
	}

	return string(idBytes), nil
}

// GetDIDRecords retrieves the didDoc records containing name and didID.
func (s *Store) GetDIDRecords() []*Record {
	itr, err := s.store.Query(didNameKey)
	if err != nil {
		return nil
	}

	defer func() {
		errClose := itr.Close()
		if errClose != nil {
			logger.Errorf("failed to close iterator: %s", errClose.Error())
		}
	}()

	var records []*Record

	more, err := itr.Next()
	if err != nil {
		return nil
	}

	for more {
		name, err := itr.Key()
		if err != nil {
			return nil
		}

		id, err := itr.Value()
		if err != nil {
			return nil
		}

		record := &Record{
			Name: getDIDName(name),
			ID:   string(id),
		}

		records = append(records, record)

		more, err = itr.Next()
		if err != nil {
			return nil
		}
	}

	return records
}

func didNameDataKey(name string) string {
	return fmt.Sprintf(didNameKeyPattern, name)
}

func getDIDName(dataKey string) string {
	return dataKey[len(didNameKey):]
}
