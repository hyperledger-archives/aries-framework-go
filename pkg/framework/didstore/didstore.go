/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didstore

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didstore"
)

// didStoreOpts holds the options for did store instance
type didStoreOpts struct {
	didMethods []didstore.DidMethod
}

// Opt is a resolver instance option
type Opt func(opts *didStoreOpts)

// WithDidMethod to add did method
// DID methods are checked in the order added
func WithDidMethod(method didstore.DidMethod) Opt {
	return func(opts *didStoreOpts) {
		opts.didMethods = append(opts.didMethods, method)
	}
}

// DIDStore did store
type DIDStore struct {
	didMethods []didstore.DidMethod
}

// New return new instance of did store
func New(opts ...Opt) *DIDStore {
	storeOpts := &didStoreOpts{didMethods: make([]didstore.DidMethod, 0)}
	// Apply options
	for _, opt := range opts {
		opt(storeOpts)
	}

	return &DIDStore{didMethods: storeOpts.didMethods}
}

// Put did store
func (d *DIDStore) Put(doc *did.Doc) error {
	didMethod, err := getDidMethod(doc.ID)
	if err != nil {
		return err
	}

	for _, v := range d.didMethods {
		if v.Accept(didMethod) {
			return v.Put(doc, nil)
		}
	}

	return didstore.ErrDidMethodNotSupported
}

// Get did store
func (d *DIDStore) Get(id string) (*did.Doc, error) {
	didMethod, err := getDidMethod(id)
	if err != nil {
		return nil, err
	}

	for _, v := range d.didMethods {
		if v.Accept(didMethod) {
			doc, err := v.Get(id)
			if err != nil {
				return nil, fmt.Errorf("get did doc : %w", err)
			}

			return doc, nil
		}
	}

	return nil, didstore.ErrDidMethodNotSupported
}

func getDidMethod(didID string) (string, error) {
	didParts := strings.SplitN(didID, ":", 3)
	if len(didParts) != 3 {
		return "", errors.New("wrong format did input")
	}

	return didParts[1], nil
}
