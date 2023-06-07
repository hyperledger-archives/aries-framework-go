/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package store

import (
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// RemoteProviderStoreName is a remote provider store name.
	RemoteProviderStoreName = "remoteproviders"

	// RemoteProviderRecordTag is a tag associated with every record in the store.
	RemoteProviderRecordTag = "record"

	queryRetryBackoffInterval = 100 * time.Millisecond
	queryRetryMaxRetries      = 5
)

// RemoteProviderRecord is a record in store with remote provider info.
type RemoteProviderRecord struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
}

// RemoteProviderStore represents a repository for remote context provider operations.
type RemoteProviderStore interface {
	Get(id string) (*RemoteProviderRecord, error)
	GetAll() ([]RemoteProviderRecord, error)
	Save(endpoint string) (*RemoteProviderRecord, error)
	Delete(id string) error
}

// RemoteProviderStoreImpl is a default implementation of remote provider repository.
type RemoteProviderStoreImpl struct {
	store               storage.Store
	debugDisableBackoff bool
}

// NewRemoteProviderStore returns a new instance of RemoteProviderStoreImpl.
func NewRemoteProviderStore(storageProvider storage.Provider) (*RemoteProviderStoreImpl, error) {
	store, err := storageProvider.OpenStore(RemoteProviderStoreName)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	err = storageProvider.SetStoreConfig(RemoteProviderStoreName,
		storage.StoreConfiguration{TagNames: []string{RemoteProviderRecordTag}})
	if err != nil {
		return nil, fmt.Errorf("set store config: %w", err)
	}

	return &RemoteProviderStoreImpl{store: store}, nil
}

// Get returns a remote provider record from the underlying storage.
func (s *RemoteProviderStoreImpl) Get(id string) (*RemoteProviderRecord, error) {
	b, err := s.store.Get(id)
	if err != nil {
		return nil, fmt.Errorf("get remote provider from store: %w", err)
	}

	return &RemoteProviderRecord{
		ID:       id,
		Endpoint: string(b),
	}, nil
}

// GetAll returns all remote provider records from the underlying storage.
func (s *RemoteProviderStoreImpl) GetAll() ([]RemoteProviderRecord, error) {
	iter, err := s.store.Query(RemoteProviderRecordTag)
	if err != nil {
		return nil, fmt.Errorf("query store: %w", err)
	}

	defer func() {
		er := iter.Close()
		if er != nil {
			logger.Errorf("Failed to close iterator: %s", er.Error())
		}
	}()

	var records []RemoteProviderRecord

	for {
		if ok, err := iter.Next(); !ok || err != nil {
			if err != nil {
				return nil, fmt.Errorf("next entry: %w", err)
			}

			break
		}

		k, err := iter.Key()
		if err != nil {
			return nil, fmt.Errorf("get key: %w", err)
		}

		v, err := iter.Value()
		if err != nil {
			return nil, fmt.Errorf("get value: %w", err)
		}

		records = append(records, RemoteProviderRecord{
			ID:       k,
			Endpoint: string(v),
		})
	}

	return records, nil
}

// Save creates a new remote provider record and saves it to the underlying storage.
// If record with given endpoint already exists in the store, it is returned to the caller.
func (s *RemoteProviderStoreImpl) Save(endpoint string) (*RemoteProviderRecord, error) {
	foundRecord, err := s.findEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	if foundRecord != nil {
		return foundRecord, nil
	}

	record := &RemoteProviderRecord{
		ID:       uuid.New().String(),
		Endpoint: endpoint,
	}

	if err := s.store.Put(record.ID,
		[]byte(record.Endpoint),
		storage.Tag{Name: RemoteProviderRecordTag},
	); err != nil {
		return nil, fmt.Errorf("save new remote provider record: %w", err)
	}

	return record, nil
}

func (s RemoteProviderStoreImpl) findEndpoint(endpoint string) (*RemoteProviderRecord, error) { // nolint:gocyclo
	var (
		foundRecord *RemoteProviderRecord
		retries     backoff.BackOff
	)

	if s.debugDisableBackoff {
		retries = &backoff.StopBackOff{}
	} else {
		retries = backoff.WithMaxRetries(backoff.NewConstantBackOff(queryRetryBackoffInterval), queryRetryMaxRetries)
	}

	return foundRecord, backoff.Retry(func() error {
		iter, err := s.store.Query(RemoteProviderRecordTag)
		if err != nil {
			return fmt.Errorf("query store: %w", err)
		}

		defer func() {
			er := iter.Close()
			if er != nil {
				logger.Errorf("Failed to close iterator: %s", er.Error())
			}
		}()

		for {
			if ok, err := iter.Next(); !ok || err != nil {
				if err != nil {
					return fmt.Errorf("next entry: %w", err)
				}

				break
			}

			k, err := iter.Key()
			if err != nil {
				return fmt.Errorf("get key: %w", err)
			}

			v, err := iter.Value()
			if err != nil {
				return fmt.Errorf("get value: %w", err)
			}

			if endpoint == string(v) {
				foundRecord = &RemoteProviderRecord{
					ID:       k,
					Endpoint: string(v),
				}

				return nil
			}
		}

		return nil
	}, retries)
}

// Delete deletes a remote provider record in the underlying storage.
func (s *RemoteProviderStoreImpl) Delete(id string) error {
	if err := s.store.Delete(id); err != nil {
		return fmt.Errorf("delete remote provider record: %w", err)
	}

	return nil
}
