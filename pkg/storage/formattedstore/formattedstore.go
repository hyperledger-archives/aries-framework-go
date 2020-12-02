/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formattedstore

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

const (
	failOpenUnderlyingStore      = "failed to open underlying store: %w"
	failCloseUnderlyingStore     = "failed to close underlying store: %w"
	failCloseAllUnderlyingStores = "failed to close all underlying stores: %w"

	failFormat                         = "failed to format value: %w"
	failPutInUnderlyingStore           = "failed to put encrypted document in underlying store: %w"
	failGetFromUnderlyingStore         = "failed to get formatted value from underlying store: %w"
	failParseFormattedValue            = "failed to parse formatted value: %w"
	failDeleteInUnderlyingStore        = "failed to delete key-value pair in underlying store: %w"
	failGetIteratorFromUnderlyingStore = "failed to get iterator from underlying store: %w"
)

var logger = log.New("formatted-store")

// Formatter represents a type that can convert data between two formats.
type Formatter interface {
	FormatPair(k string, v []byte) ([]byte, error)
	ParsePair([]byte) (k string, v []byte, err error)
	GenerateEDVCompatibleID(k string) (string, error)
}

type batchSvc interface {
	Get(k string) ([]byte, error)
	Delete(k string)
	Put(s batchStore, k string, v []byte) error
}

// Option configures the formatted store.
type Option func(opts *FormattedProvider)

// WithCacheProvider option is for using caching provider.
func WithCacheProvider(cacheProvider storage.Provider) Option {
	return func(opts *FormattedProvider) {
		opts.cacheProvider = cacheProvider
	}
}

// WithBatchWrite option is for batch write.
func WithBatchWrite(batchSize int, batchTime time.Duration) Option {
	return func(opts *FormattedProvider) {
		opts.batchSize = batchSize
		opts.batchTime = batchTime
	}
}

// FormattedProvider is a storage provider that allows for data to be formatted in an underlying provider.
type FormattedProvider struct {
	provider              storage.Provider
	cacheProvider         storage.Provider
	formatter             Formatter
	skipIteratorFiltering bool
	batchSize             int
	batchTime             time.Duration
	batchSvc              batchSvc
}

// NewFormattedProvider instantiates a new FormattedProvider with the given Provider and Formatter.
// The Formatter is used to format data before being sent to the Provider for storage.
// The Formatter is also used to restore the original format of data being retrieved from Provider.
// If the underlying provider already does filtering using the startKey and endKey parameters in its
// Iterator(startKey, endKey string) method, then set skipIteratorFiltering to true to avoid redundant
// filtering in FormattedProvider.
func NewFormattedProvider(provider storage.Provider, formatter Formatter,
	skipIteratorFiltering bool, opts ...Option) *FormattedProvider {
	formattedProvider := &FormattedProvider{
		provider:              provider,
		formatter:             formatter,
		skipIteratorFiltering: skipIteratorFiltering,
	}

	for _, opt := range opts {
		opt(formattedProvider)
	}

	if formattedProvider.batchSize > 0 {
		formattedProvider.batchSvc = NewBatchWrite(formattedProvider.batchSize, formattedProvider.batchTime,
			formatter, provider.(batchProvider))
	}

	return formattedProvider
}

// OpenStore opens a store in the underlying provider with the given name and returns a handle to it.
func (p *FormattedProvider) OpenStore(name string) (storage.Store, error) {
	store, err := p.provider.OpenStore(name)
	if err != nil {
		return nil, fmt.Errorf(failOpenUnderlyingStore, err)
	}

	formatStore := formatStore{
		store:                 store,
		formatter:             p.formatter,
		skipIteratorFiltering: p.skipIteratorFiltering,
		batchSvc:              p.batchSvc,
	}

	if p.cacheProvider != nil {
		cacheStore, err := p.cacheProvider.OpenStore(name)
		if err != nil {
			return nil, fmt.Errorf(failOpenUnderlyingStore, err)
		}

		formatStore.cacheStore = cacheStore
	}

	return &formatStore, nil
}

// CloseStore closes the store with the given name in the underlying provider.
func (p *FormattedProvider) CloseStore(name string) error {
	err := p.provider.CloseStore(name)
	if err != nil {
		return fmt.Errorf(failCloseUnderlyingStore, err)
	}

	if p.cacheProvider != nil {
		if err := p.cacheProvider.CloseStore(name); err != nil {
			return fmt.Errorf(failCloseUnderlyingStore, err)
		}
	}

	return nil
}

// Close closes all stores created in the underlying provider.
func (p *FormattedProvider) Close() error {
	err := p.provider.Close()
	if err != nil {
		return fmt.Errorf(failCloseAllUnderlyingStores, err)
	}

	if p.cacheProvider != nil {
		if err := p.cacheProvider.Close(); err != nil {
			return fmt.Errorf(failCloseAllUnderlyingStores, err)
		}
	}

	return nil
}

type formatStore struct {
	store                 storage.Store
	cacheStore            storage.Store
	formatter             Formatter
	skipIteratorFiltering bool
	batchSvc              batchSvc
}

func (s *formatStore) Put(k string, v []byte) error {
	if s.batchSvc != nil {
		if err := s.batchSvc.Put(s.store.(batchStore), k, v); err != nil {
			return err
		}
	} else {
		formattedValue, err := s.formatter.FormatPair(k, v)
		if err != nil {
			return fmt.Errorf(failFormat, err)
		}

		err = s.store.Put(k, formattedValue)
		if err != nil {
			return fmt.Errorf(failPutInUnderlyingStore, err)
		}
	}

	// put data in cache to retrieve it from Get
	if s.cacheStore != nil {
		if err := s.cacheStore.Put(k, v); err != nil {
			return err
		}
	}

	return nil
}

func (s *formatStore) Get(k string) ([]byte, error) {
	if s.cacheStore != nil {
		v, err := s.cacheStore.Get(k)
		if err == nil {
			return v, nil
		}

		logger.Debugf("failed to get key %s from cache store", k)
	}

	if s.batchSvc != nil {
		v, err := s.batchSvc.Get(k)
		if err == nil {
			return v, nil
		}

		if errors.Is(err, ErrValueIsDeleted) {
			return nil, storage.ErrDataNotFound
		}

		logger.Debugf("failed to get key %s from batch", k)
	}

	formattedValue, err := s.store.Get(k)
	if err != nil {
		return nil, fmt.Errorf(failGetFromUnderlyingStore, err)
	}

	_, value, err := s.formatter.ParsePair(formattedValue)
	if err != nil {
		return nil, fmt.Errorf(failParseFormattedValue, err)
	}

	// put data in cache to retrieve it next time
	if s.cacheStore != nil {
		if err := s.cacheStore.Put(k, value); err != nil {
			return nil, err
		}
	}

	return value, nil
}

// The "don't filter" switch is here since it's possible for the underlying storage to have already done
// the filtering, in which case it would be redundant to do it here too.
// TODO (#2315) While doing the storage interface rework, see if the skipIteratorFiltering switch is still
//  needed.
func (s *formatStore) Iterator(startKey, endKey string) storage.StoreIterator { //nolint: gocyclo
	if s.cacheStore != nil {
		r := s.cacheStore.Iterator(startKey, endKey)
		if r.Error() == nil {
			return r
		}

		logger.Debugf("failed to get iterator startKey %s endKey %s from cache store", startKey, endKey)
	}

	formattedIterator := s.store.Iterator(startKey, endKey)

	err := formattedIterator.Error()
	if err != nil {
		return mem.NewMemIterator(nil, fmt.Errorf(failGetIteratorFromUnderlyingStore, err))
	}

	var batch [][]string

	for formattedIterator.Next() {
		key, value, err := s.formatter.ParsePair(formattedIterator.Value())
		if err != nil {
			return mem.NewMemIterator(nil, fmt.Errorf(failParseFormattedValue, err))
		}

		if s.skipIteratorFiltering {
			batch = append(batch, []string{key, string(value)})
		} else {
			if endKey == "" {
				return mem.NewMemIterator(nil, nil)
			}

			if strings.HasPrefix(key, strings.TrimSuffix(endKey, storage.EndKeySuffix)) && key != endKey {
				batch = append(batch, []string{key, string(value)})
				continue
			}

			if key >= startKey && key < endKey {
				batch = append(batch, []string{key, string(value)})
			}
		}
	}

	formattedIterator.Release()

	return mem.NewMemIterator(batch, nil)
}

func (s *formatStore) Delete(k string) error {
	if s.batchSvc != nil {
		s.batchSvc.Delete(k)
	} else {
		err := s.store.Delete(k)
		if err != nil {
			return fmt.Errorf(failDeleteInUnderlyingStore, err)
		}
	}

	if s.cacheStore != nil {
		if err := s.cacheStore.Delete(k); err != nil {
			return err
		}
	}

	return nil
}
