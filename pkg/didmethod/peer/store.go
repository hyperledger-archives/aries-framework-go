/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didstore"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	// StoreNamespace store name space for DID Store
	StoreNamespace = "didresolver"
)

type docDelta struct {
	Change     string                 `json:"change,omitempty"`
	ModifiedBy *[]didstore.ModifiedBy `json:"by,omitempty"`
	ModifiedAt time.Time              `json:"when,omitempty"`
}

// DIDStore Peer DID Document store
type DIDStore struct {
	store storage.Store
}

// NewDIDStore new Peer DID store (backing store is configurable)
func NewDIDStore(s storage.Provider) (*DIDStore, error) {
	didDBStore, err := s.OpenStore(StoreNamespace)
	if err != nil {
		return nil, fmt.Errorf("open store : %w", err)
	}

	return &DIDStore{
		store: didDBStore,
	}, nil
}

// Put saves Peer DID Document along with user key/signature.
func (s *DIDStore) Put(doc *did.Doc, by *[]didstore.ModifiedBy) error {
	if doc == nil || doc.ID == "" {
		return errors.New("DID and document are mandatory")
	}

	var deltas []docDelta

	// For now, assume the doc is a genesis document
	jsonDoc, err := doc.JSONBytes()
	if err != nil {
		return fmt.Errorf("JSON marshalling of document failed: %w", err)
	}

	docDelta := &docDelta{
		Change:     base64.URLEncoding.EncodeToString(jsonDoc),
		ModifiedBy: by,
		ModifiedAt: time.Now(),
	}

	deltas = append(deltas, *docDelta)

	val, err := json.Marshal(deltas)
	if err != nil {
		return fmt.Errorf("JSON marshalling of document deltas failed: %w", err)
	}

	return s.store.Put(doc.ID, val)
}

// Get returns Peer DID Document
func (s *DIDStore) Get(id string) (*did.Doc, error) {
	if id == "" {
		return nil, errors.New("ID is mandatory")
	}

	deltas, err := s.getDeltas(id)
	if err != nil {
		return nil, fmt.Errorf("delta data fetch from store failed: %w", err)
	}

	// For now, assume storage contains only one delta(genesis document)
	delta := deltas[0]

	doc, err := base64.URLEncoding.DecodeString(delta.Change)
	if err != nil {
		return nil, fmt.Errorf("decoding of document delta failed: %w", err)
	}

	document, err := did.ParseDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("document ParseDocument() failed: %w", err)
	}

	return document, nil
}

// Accept did method
func (s *DIDStore) Accept(method string) bool {
	return method == didMethod
}

func (s *DIDStore) getDeltas(id string) ([]docDelta, error) {
	val, err := s.store.Get(id)
	if err != nil {
		return nil, fmt.Errorf("fetching data from store failed: %w", err)
	}

	var deltas []docDelta

	err = json.Unmarshal(val, &deltas)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of document deltas failed: %w", err)
	}

	return deltas, nil
}
