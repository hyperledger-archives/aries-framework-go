/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/tink/go/subtle/random"

	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms"
)

const maxKeyIDLen = 50

// newWriter creates a new instance of local storage key storeWriter in the given store and for primaryKeyURI.
func newWriter(kmsStore kmsapi.Store, opts ...kmsapi.PrivateKeyOpts) *storeWriter {
	pOpts := kmsapi.NewOpt()

	for _, opt := range opts {
		opt(pOpts)
	}

	return &storeWriter{
		storage:           kmsStore,
		requestedKeysetID: pOpts.KsID(),
	}
}

// storeWriter struct to store a keyset in a local store.
type storeWriter struct {
	storage kmsapi.Store
	//
	requestedKeysetID string
	// KeysetID is set when Write() is called
	KeysetID string
}

// Write a marshaled keyset p in localstore with primaryKeyURI prefix + randomly generated KeysetID.
func (l *storeWriter) Write(p []byte) (int, error) {
	var err error

	var ksID string

	if l.requestedKeysetID != "" {
		ksID, err = l.verifyRequestedID()
		if err != nil {
			return 0, err
		}
	} else {
		ksID, err = l.newKeysetID()
		if err != nil {
			return 0, err
		}
	}

	err = l.storage.Put(ksID, p)
	if err != nil {
		return 0, err
	}

	l.KeysetID = ksID

	return len(p), nil
}

func (l *storeWriter) verifyRequestedID() (string, error) {
	_, err := l.storage.Get(l.requestedKeysetID)
	if errors.Is(err, kms.ErrKeyNotFound) {
		return l.requestedKeysetID, nil
	}

	if err != nil {
		return "", fmt.Errorf("got error while verifying requested ID: %w", err)
	}

	return "", fmt.Errorf("requested ID '%s' already exists, cannot write keyset", l.requestedKeysetID)
}

func (l *storeWriter) newKeysetID() (string, error) {
	keySetIDLength := base64.RawURLEncoding.DecodedLen(maxKeyIDLen)

	var ksID string

	for {
		// generate random ID
		ksID = base64.RawURLEncoding.EncodeToString(random.GetRandomBytes(uint32(keySetIDLength)))

		// ensure ksID is not already used
		_, err := l.storage.Get(ksID)
		if err != nil {
			if errors.Is(err, kms.ErrKeyNotFound) {
				break
			}

			return "", err
		}
	}

	return ksID, nil
}
