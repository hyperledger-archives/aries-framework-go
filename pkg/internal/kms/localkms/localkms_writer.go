/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"encoding/base64"
	"fmt"

	"github.com/google/tink/go/subtle/random"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// NewWriter creates a new instance of local storage key writer in the given store and for masterKeyURI
func NewWriter(kmsStore storage.StoreWithDelete, masterKeyURI string) *Writer {
	return &Writer{
		storage:      kmsStore,
		masterKeyURI: masterKeyURI,
	}
}

// Writer struct to store a keyset in a local store
type Writer struct {
	storage      storage.StoreWithDelete
	masterKeyURI string
	// KeysetID is set when Write() is called
	KeysetID string
}

// Write p in localstore with masterKeyURI prefix + randomly generated KeysetID
func (l *Writer) Write(p []byte) (int, error) {
	if l.masterKeyURI == "" {
		return 0, fmt.Errorf("master key is not set")
	}

	const keySetIDLength = 32

	baseID := l.masterKeyURI + "/"
	ksID := ""

	for {
		ksID = baseID + base64.URLEncoding.EncodeToString(random.GetRandomBytes(keySetIDLength)) // generate random ID

		// ensure ksID is not already used
		_, e := l.storage.Get(ksID)
		if e != nil {
			if e == storage.ErrDataNotFound {
				break
			}

			return 0, e
		}
	}

	err := l.storage.Put(ksID, p)
	if err != nil {
		return 0, err
	}

	l.KeysetID = ksID

	return len(p), nil
}
