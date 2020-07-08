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
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

type docDelta struct {
	Change     string                `json:"change,omitempty"`
	ModifiedBy *[]vdriapi.ModifiedBy `json:"by,omitempty"`
	ModifiedAt time.Time             `json:"when,omitempty"`
}

// Store saves Peer DID Document along with user key/signature.
func (v *VDRI) Store(doc *did.Doc, by *[]vdriapi.ModifiedBy) error {
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

	return v.store.Put(doc.ID, val)
}

// Get returns Peer DID Document
func (v *VDRI) Get(id string) (*did.Doc, error) {
	if id == "" {
		return nil, errors.New("ID is mandatory")
	}

	deltas, err := v.getDeltas(id)
	if err != nil {
		return nil, fmt.Errorf("delta data fetch from store for did [%s] failed: %w", id, err)
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

// Close frees resources being maintained by vdri.
func (v *VDRI) Close() error {
	return nil
}

func (v *VDRI) getDeltas(id string) ([]docDelta, error) {
	val, err := v.store.Get(id)
	if errors.Is(err, storage.ErrDataNotFound) {
		return nil, vdriapi.ErrNotFound
	}

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
