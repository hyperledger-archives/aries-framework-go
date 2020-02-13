/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/google/tink/go/subtle/random"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// newWriter creates a new instance of local storage key storeWriter in the given store and for masterKeyURI
func newWriter(kmsStore storage.Store, masterKeyURI string) *storeWriter {
	mkURI := masterKeyURI
	if strings.LastIndex(mkURI, "/") < len(mkURI)-1 {
		mkURI += "/"
	}

	return &storeWriter{
		storage:      kmsStore,
		masterKeyURI: mkURI,
	}
}

// storeWriter struct to store a keyset in a local store
type storeWriter struct {
	storage      storage.Store
	masterKeyURI string
	// KeysetID is set when Write() is called
	KeysetID string
}

// Write a marshaled keyset p in localstore with masterKeyURI prefix + randomly generated KeysetID
func (l *storeWriter) Write(p []byte) (int, error) {
	if l.masterKeyURI == "" {
		return 0, fmt.Errorf("master key is not set")
	}

	const keySetIDLength = 32

	baseID := l.masterKeyURI
	ksID := ""

	for {
		// generate random ID prefixed with masterKeyURI
		ksID = baseID + base64.URLEncoding.EncodeToString(random.GetRandomBytes(keySetIDLength))

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
