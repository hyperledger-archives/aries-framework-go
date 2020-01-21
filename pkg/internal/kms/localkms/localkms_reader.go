/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// NewReader will create a new local storage reader of a keyset with ID value = keysetID
func NewReader(store storage.Store, keysetID string) *Reader {
	return &Reader{
		storage:  store,
		keysetID: keysetID,
	}
}

// Reader struct to load a keyset from a local storage
type Reader struct {
	buf      []byte
	lastRead int
	storage  storage.Store
	keysetID string
}

// Read p from local storage representing a keyset with ID = l.keysetID
func (l *Reader) Read(p []byte) (int, error) {
	if l.keysetID == "" {
		return 0, fmt.Errorf("keysetID is not set")
	}

	// populate buf if empty
	if len(l.buf) == 0 {
		data, err := l.storage.Get(l.keysetID)
		if err != nil {
			return 0, err
		}

		capLengthFactor := 2
		l.buf = make([]byte, len(data), capLengthFactor*len(data))
		copy(l.buf, data)
	}

	var copiedBytes int
	// read unconsumed buf
	if l.lastRead < len(l.buf) {
		copiedBytes = copy(p, l.buf[l.lastRead:])

		l.lastRead += copiedBytes
		if l.lastRead >= len(l.buf) {
			// reset buf and lastRead
			l.lastRead = 0
			l.buf = nil

			return copiedBytes, io.EOF
		}
	}

	return copiedBytes, nil
}
