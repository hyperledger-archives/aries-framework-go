/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formattedstore

import (
	"fmt"
	"sync"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/storage/edv/models"
)

// ErrValueIsDeleted is returned when value is deleted.
var ErrValueIsDeleted = fmt.Errorf("value is deleted")

type batchProvider interface {
	Batch(batch *models.Batch) error
}

type batchStore interface {
	AddEncryptedIndexTagForStoreName(encryptedDocumentBytes []byte) (*models.EncryptedDocument, error)
}

// BatchService is a batch service.
type BatchService struct {
	mutex            sync.RWMutex
	futureValues     map[string]*batch
	futureValuesLock sync.RWMutex
	formatter        Formatter
	provider         batchProvider // TODO remove batch provider after refactoring edv batch
	current          *pendingBatch
	batchSizeLimit   int
}

type batch struct {
	keyID                   string
	value                   []byte
	isDeleted               bool
	addEncryptedIndicesFunc func(encryptedDocumentBytes []byte) (*models.EncryptedDocument, error)
}

// NewBatchWrite new batch write.
//nolint: funlen
func NewBatchWrite(batchSizeLimit int, formatter Formatter, provider batchProvider) *BatchService {
	b := &BatchService{
		futureValues: make(map[string]*batch), formatter: formatter, provider: provider,
		current: newPendingBatch(provider, formatter), batchSizeLimit: batchSizeLimit,
	}

	return b
}

// Get value from batch values.
func (b *BatchService) Get(k string) ([]byte, error) {
	b.futureValuesLock.RLock()
	v, ok := b.futureValues[k]
	b.futureValuesLock.RUnlock()

	if !ok {
		return nil, fmt.Errorf("k %s not found", k)
	}

	if v.isDeleted {
		return nil, ErrValueIsDeleted
	}

	return v.value, nil
}

// Put in batch value.
func (b *BatchService) Put(s batchStore, k string, v []byte) error {
	addBatch := &batch{keyID: k, value: v, isDeleted: false, addEncryptedIndicesFunc: s.AddEncryptedIndexTagForStoreName}
	start := time.Now()

	b.futureValuesLock.Lock()
	b.futureValues[k] = addBatch
	b.futureValuesLock.Unlock()

	if err := b.currentBatch().put(addBatch); err != nil {
		return err
	}

	if b.batchSizeLimit > 0 && b.currentBatch().size >= b.batchSizeLimit {
		if err := b.Flush(); err != nil {
			return err
		}
	}

	logger.Infof("batch write put duration %s", time.Since(start))

	return nil
}

// Delete value.
func (b *BatchService) Delete(k string) error {
	addBatch := &batch{keyID: k, isDeleted: true}

	b.futureValuesLock.Lock()
	b.futureValues[k] = addBatch
	b.futureValuesLock.Unlock()

	if err := b.currentBatch().delete(addBatch); err != nil {
		return err
	}

	if b.batchSizeLimit > 0 && b.currentBatch().size >= b.batchSizeLimit {
		if err := b.Flush(); err != nil {
			return err
		}
	}

	return nil
}

// Flush data.
func (b *BatchService) Flush() error {
	start := time.Now()

	current := b.currentBatch()

	err := current.flush()

	logger.Infof("batch write flush waiting duration for batch to be ready %s", time.Since(start))

	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.current = newPendingBatch(b.provider, b.formatter)

	b.futureValuesLock.Lock()
	b.futureValues = make(map[string]*batch)
	b.futureValuesLock.Unlock()

	return err
}

func (b *BatchService) currentBatch() *pendingBatch {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	return b.current
}

type pendingBatch struct {
	provider  batchProvider
	formatter Formatter
	values    models.Batch
	mutex     sync.RWMutex
	size      int
}

func newPendingBatch(provider batchProvider, formatter Formatter) *pendingBatch {
	logger.Infof("Creating new pending batch")

	return &pendingBatch{
		provider:  provider,
		formatter: formatter,
		size:      0,
	}
}

func (p *pendingBatch) put(addBatch *batch) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.size++

	formattedValue, err := p.formatter.FormatPair(addBatch.keyID, addBatch.value)
	if err != nil {
		return err
	}

	encryptedDocument, err := addBatch.addEncryptedIndicesFunc(formattedValue)
	if err != nil {
		return err
	}

	p.values = append(p.values, models.VaultOperation{
		Operation:         models.UpsertDocumentVaultOperation,
		EncryptedDocument: *encryptedDocument,
	})

	return nil
}

func (p *pendingBatch) delete(addBatch *batch) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.size++

	id, err := p.formatter.GenerateEDVDocumentID(addBatch.keyID)
	if err != nil {
		return err
	}

	p.values = append(p.values, models.VaultOperation{
		Operation:  models.DeleteDocumentVaultOperation,
		DocumentID: id,
	})

	return nil
}

func (p *pendingBatch) flush() error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	logger.Debugf("Flushing %d items", len(p.values))

	if len(p.values) == 0 {
		// Nothing to do
		return nil
	}

	start := time.Now()

	// call edv server to commit the batch
	err := p.provider.Batch(&p.values)

	logger.Infof("batch write flush batch %d rest call duration %s", len(p.values), time.Since(start))

	return err
}
