/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package packer

import (
	"encoding/base64"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
)

// note: does not replicate correct packing
// when msg needs to be escaped.
func testPack(msg, key []byte) []byte {
	headerValue := base64.URLEncoding.EncodeToString([]byte(`{"typ":"NOOP"}`))

	return []byte(`{"protected":"` + headerValue +
		`","spk":"` + base58.Encode(key) +
		`","msg":"` + string(msg) + `"}`)
}

func TestPacker(t *testing.T) {
	p := New(nil)
	require.NotNil(t, p)
	require.Equal(t, encodingType, p.EncodingType())

	t.Run("pack, compare against correct data", func(t *testing.T) {
		msgin := []byte("hello my name is zoop")
		key := []byte("senderkey")

		msgout, err := p.Pack(msgin, key, nil)
		require.NoError(t, err)

		correct := testPack(msgin, key)
		require.Equal(t, correct, msgout)
	})

	t.Run("unpack fixed value, confirm data", func(t *testing.T) {
		correct := []byte("this is not a test message")
		key := []byte("testKey")
		msgin := testPack(correct, key)

		msgout, keyOut, err := p.Unpack(msgin)
		require.NoError(t, err)

		require.Equal(t, correct, msgout)
		require.Equal(t, key, keyOut)
	})

	t.Run("multiple pack/unpacks", func(t *testing.T) {
		cleartext := []byte("this is not a test message")
		key1 := []byte("testKey")
		key2 := []byte("wrapperKey")

		correct1 := testPack(cleartext, key1)

		msg1, err := p.Pack(cleartext, key1, nil)
		require.NoError(t, err)
		require.Equal(t, correct1, msg1)

		msg2, err := p.Pack(msg1, key2, nil)
		require.NoError(t, err)

		msg3, key1Out, err := p.Unpack(msg2)
		require.NoError(t, err)
		require.Equal(t, key2, key1Out)
		require.Equal(t, correct1, msg3)

		msg4, key2Out, err := p.Unpack(msg3)
		require.NoError(t, err)
		require.Equal(t, key1, key2Out)
		require.Equal(t, cleartext, msg4)
	})
}
