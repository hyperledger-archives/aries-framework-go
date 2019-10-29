/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didstore

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// ErrDidMethodNotSupported is returned when a DID method not supported
var ErrDidMethodNotSupported = errors.New("did method not supported")

// ModifiedBy key/signature used to update the DID Document
type ModifiedBy struct {
	Key string `json:"key,omitempty"`
	Sig string `json:"sig,omitempty"`
}

// Storage expose did store methods
type Storage interface {
	Put(doc *did.Doc) error
	Get(id string) (*did.Doc, error)
}

// DidMethod expose did method store methods
type DidMethod interface {
	Put(doc *did.Doc, by *[]ModifiedBy) error
	Get(id string) (*did.Doc, error)
	Accept(method string) bool
}
