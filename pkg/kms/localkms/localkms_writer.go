/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"encoding/base64"

	"github.com/google/tink/go/subtle/random"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const maxKeyIDLen = 20

// newWriter creates a new instance of local storage key storeWriter in the given store and for masterKeyURI
func newWriter(kmsStore storage.Store) *storeWriter {
	return &storeWriter{
		storage: kmsStore,
	}
}

// storeWriter struct to store a keyset in a local store
type storeWriter struct {
	storage storage.Store
	// KeysetID is set when Write() is called
	KeysetID string
}

// Write a marshaled keyset p in localstore with masterKeyURI prefix + randomly generated KeysetID
func (l *storeWriter) Write(p []byte) (int, error) {
	keySetIDLength := base64.RawURLEncoding.DecodedLen(maxKeyIDLen)
	ksID := ""

	for {
		// generate random ID
		ksID = base64.RawURLEncoding.EncodeToString(random.GetRandomBytes(uint32(keySetIDLength)))

		// skip IDs starting with '_' as some storage types reserve them for indexes (eg couchdb)
		if ksID[0] == '_' {
			continue
		}

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
