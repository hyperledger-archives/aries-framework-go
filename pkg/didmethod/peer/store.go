/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	errors "golang.org/x/xerrors"
)

// DIDModifiedBy key/signature used to update the Peer DID Document
type DIDModifiedBy struct {
	Key string `json:"key,omitempty"`
	Sig string `json:"sig,omitempty"`
}

type docDelta struct {
	Change     string           `json:"change,omitempty"`
	ModifiedBy *[]DIDModifiedBy `json:"by,omitempty"`
	ModifiedAt time.Time        `json:"when,omitempty"`
}

// DIDStore Peer DID Document store
type DIDStore struct {
	store storage.Store
}

// NewDIDStore new Peer DID store (backing store is configurable)
func NewDIDStore(s storage.Store) *DIDStore {
	return &DIDStore{
		store: s,
	}
}

// Put saves Peer DID Document along with user key/signature
func (s *DIDStore) Put(did string, doc *did.Doc, by *[]DIDModifiedBy) error {
	if did == "" || doc == nil {
		return errors.New("DID and Document are mandatory")
	}

	var deltas []docDelta

	// TODO - Need to derive the docDelta if its not a genesis document(DID already exists)
	// (https://github.com/hyperledger/aries-framework-go/issues/54)
	// For now, assume the doc is a genesis document
	jsonDoc, err := json.Marshal(doc)
	if err != nil {
		return errors.Errorf("Json marshalling of document failed: %w", err)
	}

	docDelta := &docDelta{
		Change:     base64.URLEncoding.EncodeToString(jsonDoc),
		ModifiedBy: by,
		ModifiedAt: time.Now(),
	}

	deltas = append(deltas, *docDelta)

	val, err := json.Marshal(deltas)
	if err != nil {
		return errors.Errorf("Json marshalling of document deltas failed: %w", err)
	}

	return s.store.Put(did, val)
}

// Get returns Peer DID Document
func (s *DIDStore) Get(id string) (*did.Doc, error) {
	if id == "" {
		return nil, errors.New("ID is mandatory")
	}

	deltas, err := s.getDeltas(id)
	if err != nil {
		return nil, errors.Errorf("Delta data fetch from store failed : %w", err)
	}

	// TODO construct document from all the deltas (https://github.com/hyperledger/aries-framework-go/issues/54)
	// For now, assume storage contains only one delta(genesis document)
	delta := deltas[0]

	doc, err := base64.URLEncoding.DecodeString(delta.Change)
	if err != nil {
		return nil, errors.Errorf("Decoding of document delta failed: %w", err)
	}

	document := &did.Doc{}
	err = json.Unmarshal(doc, document)
	if err != nil {
		return nil, errors.Errorf("Json unmarshalling of document failed: %w", err)
	}

	return document, nil
}

func (s *DIDStore) getDeltas(id string) ([]docDelta, error) {
	val, err := s.store.Get(id)
	if err != nil {
		return nil, errors.Errorf("Fetching data from store failed: %w", err)
	}

	var deltas []docDelta
	err = json.Unmarshal(val, &deltas)
	if err != nil {
		return nil, errors.Errorf("Json unmarshalling of document deltas failed: %w", err)
	}

	return deltas, nil
}
