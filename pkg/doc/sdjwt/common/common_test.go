/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
)

const defaultHash = crypto.SHA256

func TestGetHash(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		digest, err := GetHash(defaultHash, "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0")
		require.NoError(t, err)
		require.Equal(t, "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY", digest)
	})

	t.Run("error - hash not available", func(t *testing.T) {
		digest, err := GetHash(0, "test")
		require.Error(t, err)
		require.Empty(t, digest)
		require.Contains(t, err.Error(), "hash function not available for: 0")
	})
}

func TestParseSDJWT(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		sdJWT := ParseSDJWT(sdJWT)
		require.Equal(t, 1, len(sdJWT.Disclosures))
	})
}

// nolint: lll
const sdJWT = `eyJhbGciOiJFZERTQSJ9.eyJfc2QiOlsicXF2Y3FuY3pBTWdZeDdFeWtJNnd3dHNweXZ5dks3OTBnZTdNQmJRLU51cyJdLCJfc2RfYWxnIjoic2hhLTI1NiIsImV4cCI6MTcwMzAyMzg1NSwiaWF0IjoxNjcxNDg3ODU1LCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsIm5iZiI6MTY3MTQ4Nzg1NX0.vscuzfwcHGi04pWtJCadc4iDELug6NH6YK-qxhY1qacsciIHuoLELAfon1tGamHtuu8TSs6OjtLk3lHE16jqAQ~WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd`
