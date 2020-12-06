/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formattedstore

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

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

type processBatch struct {
	id             string
	vaultOperation *models.VaultOperation
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

	b.currentBatch().put(addBatch)

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

	b.currentBatch().delete(addBatch)

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
	values    []*processBatch
	wg        sync.WaitGroup
	mutex     sync.RWMutex
	err       error
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

func (p *pendingBatch) put(addBatch *batch) {
	p.size++

	p.wg.Add(1)

	p.mutex.Lock()

	processID := uuid.New().String()

	p.values = append(p.values, &processBatch{id: "ready_" + processID, vaultOperation: &models.VaultOperation{
		Operation: models.UpsertDocumentVaultOperation,
	}})

	p.mutex.Unlock()

	go func(addBatch *batch, processID string) {
		logger.Infof("start format pair for put k %s", addBatch.keyID)

		formattedValue, err := p.formatter.FormatPair(addBatch.keyID, addBatch.value)
		if err != nil {
			logger.Errorf("failed to format pair for k=%s: %w", addBatch.keyID, err)

			p.doneWithError(err)

			return
		}

		encryptedDocument, err := addBatch.addEncryptedIndicesFunc(formattedValue)
		if err != nil {
			logger.Errorf("failed to add encrypted indices k=%s: %w", addBatch.keyID, err)

			p.doneWithError(err)

			return
		}

		p.done(processID, encryptedDocument)
	}(addBatch, processID)
}

func (p *pendingBatch) delete(addBatch *batch) {
	p.size++

	id, err := p.formatter.GenerateEDVDocumentID(addBatch.keyID)
	if err != nil {
		logger.Errorf("failed to generate edv compatible id: %s", err)

		p.mutex.Lock()
		p.err = err
		p.mutex.Unlock()

		return
	}

	p.mutex.Lock()

	p.values = append(p.values, &processBatch{id: "ready", vaultOperation: &models.VaultOperation{
		Operation:  models.DeleteDocumentVaultOperation,
		DocumentID: id,
	}})

	p.mutex.Unlock()
}

func (p *pendingBatch) flush() error {
	p.wg.Wait()

	p.mutex.RLock()
	defer p.mutex.RUnlock()

	logger.Debugf("Flushing %d items", len(p.values))

	if p.err != nil {
		logger.Infof("Pending batch has errors: %s", p.err)

		return p.err
	}

	if len(p.values) == 0 {
		// Nothing to do
		return nil
	}

	start := time.Now()

	var readyBatch models.Batch

	for _, v := range p.values {
		readyBatch = append(readyBatch, *v.vaultOperation)
	}

	// call edv server to commit the batch
	err := p.provider.Batch(&readyBatch)

	logger.Infof("batch write flush batch %d rest call duration %s", len(p.values), time.Since(start))

	return err
}

func (p *pendingBatch) done(processID string, encryptedDocument *models.EncryptedDocument) {
	p.mutex.Lock()

	for i, v := range p.values {
		if v.id == "ready_"+processID {
			p.values[i].id = "ready"
			p.values[i].vaultOperation.EncryptedDocument = *encryptedDocument

			break
		}
	}

	p.mutex.Unlock()

	p.wg.Done()
}

func (p *pendingBatch) doneWithError(err error) {
	p.mutex.Lock()
	p.err = err
	p.mutex.Unlock()

	p.wg.Done()
}
