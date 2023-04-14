/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"bytes"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/kms"
)

// newReader will create a new local storage storeReader of a keyset with ID value = keysetID
// it is used internally by local kms.
func newReader(store kms.Store, keysetID string) *storeReader {
	return &storeReader{
		storage:  store,
		keysetID: keysetID,
	}
}

// storeReader struct to load a keyset from a local storage.
type storeReader struct {
	buf      *bytes.Buffer
	storage  kms.Store
	keysetID string
}

// Read the keyset from local storage into p.
func (l *storeReader) Read(p []byte) (int, error) {
	if l.buf == nil {
		if l.keysetID == "" {
			return 0, fmt.Errorf("keysetID is not set")
		}

		data, err := l.storage.Get(l.keysetID)
		if err != nil {
			return 0, fmt.Errorf("cannot read data for keysetID %s: %w", l.keysetID, err)
		}

		l.buf = bytes.NewBuffer(data)
	}

	return l.buf.Read(p)
}
