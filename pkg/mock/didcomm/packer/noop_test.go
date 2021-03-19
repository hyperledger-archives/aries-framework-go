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
func testPack(cty string, msg, senderKey, recKey []byte) []byte {
	headerValue := base64.URLEncoding.EncodeToString([]byte(`{"typ":"NOOP","cty":"` + cty + `"}`))

	return []byte(`{"protected":"` + headerValue +
		`","spk":"` + base58.Encode(senderKey) +
		`","kid":"` + base58.Encode(recKey) +
		`","msg":"` + string(msg) + `"}`)
}

func TestPacker(t *testing.T) {
	defaultContentType := "plaintext"
	p := New(nil)
	require.NotNil(t, p)
	require.Equal(t, encodingType, p.EncodingType())

	t.Run("no rec keys", func(t *testing.T) {
		_, err := p.Pack("", nil, nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no recipients")
	})

	t.Run("pack, compare against correct data", func(t *testing.T) {
		msgin := []byte("hello my name is zoop")
		key := []byte("senderkey")
		rec := []byte("recipient")

		msgout, err := p.Pack(defaultContentType, msgin, key, [][]byte{rec})
		require.NoError(t, err)

		correct := testPack(defaultContentType, msgin, key, rec)
		require.Equal(t, correct, msgout)
	})

	t.Run("unpack fixed value, confirm data", func(t *testing.T) {
		correct := []byte("this is not a test message")
		key := []byte("testKey")
		rec := []byte("key2")
		msgin := testPack(defaultContentType, correct, key, rec)

		envOut, err := p.Unpack(msgin)
		require.NoError(t, err)

		require.Equal(t, correct, envOut.Message)
		require.Equal(t, key, envOut.FromKey)
		require.Equal(t, rec, envOut.ToKey)
		require.Equal(t, defaultContentType, envOut.CTY)
	})

	t.Run("multiple pack/unpacks", func(t *testing.T) {
		cleartext := []byte("this is not a test message")
		key1 := []byte("testKey")
		rec1 := []byte("rec1")
		key2 := []byte("wrapperKey")
		rec2 := []byte("rec2")

		correct1 := testPack(defaultContentType, cleartext, key1, rec1)

		msg1, err := p.Pack(defaultContentType, cleartext, key1, [][]byte{rec1})
		require.NoError(t, err)
		require.Equal(t, correct1, msg1)

		msg2, err := p.Pack(defaultContentType, msg1, key2, [][]byte{rec2})
		require.NoError(t, err)

		env1, err := p.Unpack(msg2)
		require.NoError(t, err)
		require.Equal(t, key2, env1.FromKey)
		require.Equal(t, rec2, env1.ToKey)
		require.Equal(t, correct1, env1.Message)
		require.Equal(t, defaultContentType, env1.CTY)

		env2, err := p.Unpack(env1.Message)
		require.NoError(t, err)
		require.Equal(t, key1, env2.FromKey)
		require.Equal(t, rec1, env2.ToKey)
		require.Equal(t, cleartext, env2.Message)
		require.Equal(t, defaultContentType, env2.CTY)
	})

	t.Run("unpack errors", func(t *testing.T) {
		_, err := p.Unpack(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "end of JSON input")

		_, err = p.Unpack([]byte("{}"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "end of JSON input")

		_, err = p.Unpack([]byte("{\"protected\":\"$$$$$$$$$$$$\"}"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data")

		_, err = p.Unpack([]byte("{\"protected\":\"e3t7\"}"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
	})
}
