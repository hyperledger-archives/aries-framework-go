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
	AddEncryptedIndices(k string, encryptedDocumentBytes []byte) (*models.EncryptedDocument, error)
}

// BatchService is a batch service.
type BatchService struct {
	sizeLimit int
	timeLimit time.Duration
	sync.RWMutex
	values       models.Batch
	futureValues map[string]*batch
	formatter    Formatter
	provider     batchProvider // TODO remove batch provider after refactoring edv batch
	addBatchChan chan *batch
}

type batch struct {
	keyID                   string
	value                   []byte
	isDeleted               bool
	addEncryptedIndicesFunc func(k string, encryptedDocumentBytes []byte) (*models.EncryptedDocument, error)
}

// NewBatchWrite new batch write.
func NewBatchWrite(sizeLimit int, timeLimit time.Duration, formatter Formatter,
	provider batchProvider) *BatchService {
	ticker := time.NewTicker(timeLimit)
	quit := make(chan struct{})
	b := &BatchService{
		sizeLimit: sizeLimit, timeLimit: timeLimit, values: make(models.Batch, 0),
		futureValues: make(map[string]*batch), formatter: formatter, provider: provider,
		addBatchChan: make(chan *batch, sizeLimit),
	}

	go func(b *BatchService) {
		for {
			select {
			case <-ticker.C:
				if err := b.flush(); err != nil {
					logger.Errorf(err.Error())
				}
			case addBatch := <-b.addBatchChan:
				if addBatch.isDeleted {
					id, err := b.formatter.GenerateEDVCompatibleID(addBatch.keyID)
					if err != nil {
						logger.Errorf("failed to generate edv compatible id: %s", err)
						return
					}

					b.Lock()
					b.values = append(b.values, models.VaultOperation{
						Operation:  models.DeleteDocumentVaultOperation,
						DocumentID: id,
					})
					b.Unlock()
				} else {
					formattedValue, err := b.formatter.FormatPair(addBatch.keyID, addBatch.value)
					if err != nil {
						logger.Errorf("failed to format pair for k=%s: %w", addBatch.keyID, err)
						return
					}

					encryptedDocument, err := addBatch.addEncryptedIndicesFunc(addBatch.keyID, formattedValue)
					if err != nil {
						logger.Errorf("failed to add encrypted indices k=%s: %w", addBatch.keyID, err)
						return
					}

					b.Lock()
					b.values = append(b.values, models.VaultOperation{
						Operation:         models.UpsertDocumentVaultOperation,
						EncryptedDocument: *encryptedDocument,
					})
					b.Unlock()
				}
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}(b)

	return b
}

// Get value from batch values.
func (b *BatchService) Get(k string) ([]byte, error) {
	b.RLock()
	v, ok := b.futureValues[k]
	b.RUnlock()

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
	b.RLock()
	size := len(b.values)
	b.RUnlock()

	if size >= b.sizeLimit {
		if err := b.flush(); err != nil {
			return err
		}
	}

	addBatch := &batch{keyID: k, value: v, isDeleted: false, addEncryptedIndicesFunc: s.AddEncryptedIndices}

	b.Lock()
	b.futureValues[k] = addBatch
	b.Unlock()

	b.addBatchChan <- addBatch

	return nil
}

// Delete value.
func (b *BatchService) Delete(k string) {
	addBatch := &batch{keyID: k, isDeleted: true}

	b.Lock()
	b.futureValues[k] = addBatch
	b.Unlock()

	b.addBatchChan <- addBatch
}

func (b *BatchService) flush() error {
	start := time.Now()

	b.Lock()
	logger.Infof("flush waiting duration to acquire lock %s", time.Since(start))

	if len(b.values) != 0 {
		start := time.Now()
		// call edv server to commit the batch
		if err := b.provider.Batch(&b.values); err != nil {
			return err
		}

		logger.Infof("flush batch %d rest call duration %s", len(b.values), time.Since(start))

		b.values = make(models.Batch, 0)
		b.futureValues = make(map[string]*batch)
	}
	b.Unlock()

	return nil
}
