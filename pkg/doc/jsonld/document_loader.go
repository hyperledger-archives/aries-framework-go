/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	"errors"
	"sync"

	"github.com/piprate/json-gold/ld"
)

// CachingDocumentLoader is similar to json-gold's CachingDocumentLoader but uses cache as *sync.Map instead.
type CachingDocumentLoader struct {
	nextLoader ld.DocumentLoader
	cache      map[string]interface{}
	rwMutex    sync.RWMutex
}

// NewCachingDocLoader creates a new instance of CachingDocumentLoader.
func NewCachingDocLoader(nextLoader ld.DocumentLoader) *CachingDocumentLoader {
	cdl := &CachingDocumentLoader{
		nextLoader: nextLoader,
		cache:      map[string]interface{}{},
	}

	return cdl
}

// LoadDocument returns a RemoteDocument containing the contents of the JSON resource from the given URL (u).
func (cdl *CachingDocumentLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	cdl.rwMutex.RLock()
	if doc, cached := cdl.cache[u]; cached {
		defer cdl.rwMutex.RUnlock()

		if cachedDoc, ok := doc.(*ld.RemoteDocument); ok {
			return cachedDoc, nil
		}

		return nil, errors.New("invalid document entry")
	}

	cdl.rwMutex.RUnlock()

	docFromLoader, err := cdl.nextLoader.LoadDocument(u)
	if err != nil {
		return nil, err
	}

	cdl.rwMutex.Lock()
	if _, cached := cdl.cache[u]; !cached {
		cdl.cache[u] = docFromLoader
	}

	cdl.rwMutex.Unlock()

	return docFromLoader, nil
}

// AddDocument populates the cache with the given document (doc) for the provided URL (u).
func (cdl *CachingDocumentLoader) AddDocument(u string, doc interface{}) {
	cdl.rwMutex.Lock()

	// add doc if u is not found in cache
	if _, cached := cdl.cache[u]; !cached {
		cdl.cache[u] = &ld.RemoteDocument{DocumentURL: u, Document: doc, ContextURL: ""}
	}

	cdl.rwMutex.Unlock()
}
