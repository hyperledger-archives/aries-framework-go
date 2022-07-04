//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prover

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	clsubtle "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/subtle"
	clpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/cl_go_proto"
)

func TestCLProverKeyManager_Primitive(t *testing.T) {
	km := newCLProverKeyManager()

	t.Run("Test prover key manager Primitive() success", func(t *testing.T) {
		p, err := km.Primitive(getKey(t, validPrimitiveParams(t)))
		require.NoError(t, err)
		require.NotEmpty(t, p)
	})

	t.Run("Test prover key manager Primitive() with nil serialized key", func(t *testing.T) {
		p, err := km.Primitive(nil)
		require.Contains(t, err.Error(), errInvalidCLProverKey.Error())
		require.Empty(t, p)
	})

	t.Run("Test prover key manager Primitive() with bad serialize key", func(t *testing.T) {
		p, err := km.Primitive([]byte("bad.data"))
		require.Contains(t, err.Error(), errInvalidCLProverKey.Error())
		require.Contains(t, err.Error(), "invalid proto: proto:")
		require.Contains(t, err.Error(), "cannot parse invalid wire-format data")
		require.Empty(t, p)
	})

	t.Run("Test prover key manager Primitive() with bad version key", func(t *testing.T) {
		p, err := km.Primitive(
			getKey(t,
				validPrimitiveParams(t).WithVersion(uint32(999)),
			),
		)
		require.Contains(t, err.Error(), errInvalidCLProverKey.Error())
		require.Contains(t, err.Error(), "invalid key version")
		require.Empty(t, p)
	})

	t.Run("Test prover key manager Primitive() with invalid ursa key", func(t *testing.T) {
		p, err := km.Primitive(
			getKey(t,
				validPrimitiveParams(t).WithKey([]byte("bad data")),
			),
		)
		require.Contains(t, err.Error(), errInvalidCLProverKey.Error())
		require.Contains(t, err.Error(), "invalid ursa key")
		require.Contains(t, err.Error(), "invalid master secret key")
		require.Empty(t, p)
	})

}

func TestCLProverKeyManager_NewKey(t *testing.T) {
	km := newCLProverKeyManager()

	t.Run("Test prover key manager NewKey() success", func(t *testing.T) {
		p, err := km.NewKey(getSerializedKeyFormat(t, validPrimitiveParams(t)))
		require.NoError(t, err)
		require.NotEmpty(t, p)
	})

	t.Run("Test prover key manager NewKey() with nil key", func(t *testing.T) {
		k, err := km.NewKey(nil)
		require.EqualError(t, err, errInvalidCLProverKeyFormat.Error())
		require.Empty(t, k)
	})

	t.Run("Test prover key manager NewKey() with bad serialize key", func(t *testing.T) {
		p, err := km.NewKey([]byte("bad.data"))
		require.Contains(t, err.Error(), errInvalidCLProverKeyFormat.Error())
		require.Contains(t, err.Error(), "invalid proto: proto:")
		require.Contains(t, err.Error(), "cannot parse invalid wire-format data")
		require.Empty(t, p)
	})
}

func TestCLProverKeyManager_NewKeyData(t *testing.T) {
	km := newCLProverKeyManager()

	t.Run("Test prover key manager NewKeyData() success", func(t *testing.T) {
		p, err := km.NewKeyData(getSerializedKeyFormat(t, validPrimitiveParams(t)))
		require.NoError(t, err)
		require.NotEmpty(t, p)
	})

	t.Run("Test prover key manager NewKeyData() with nil key", func(t *testing.T) {
		k, err := km.NewKeyData(nil)
		require.EqualError(t, err, errInvalidCLProverKeyFormat.Error())
		require.Empty(t, k)
	})

	t.Run("Test prover key manager NewKeyData() with bad serialize key", func(t *testing.T) {
		p, err := km.NewKeyData([]byte("bad.data"))
		require.Contains(t, err.Error(), errInvalidCLProverKeyFormat.Error())
		require.Contains(t, err.Error(), "invalid proto: proto:")
		require.Contains(t, err.Error(), "cannot parse invalid wire-format data")
		require.Empty(t, p)
	})

}

func TestCLProverKeyManager_DoesSupport(t *testing.T) {
	km := newCLProverKeyManager()
	require.False(t, km.DoesSupport("bad/url"))
	require.True(t, km.DoesSupport(clProverKeyTypeURL))
}

func TestCLProverKeyManager_TypeURL(t *testing.T) {
	km := newCLProverKeyManager()
	require.Equal(t, clProverKeyTypeURL, km.TypeURL())
}

type primitiveParams struct {
	Version uint32
	Key     []byte
}

func validPrimitiveParams(t *testing.T) primitiveParams {
	validVersion := uint32(0)
	validKey := clsubtle.CreateMasterSecretKeyJson(t)
	return primitiveParams{
		Version: validVersion,
		Key:     validKey,
	}
}

func (pp primitiveParams) WithVersion(version uint32) primitiveParams {
	pp.Version = version
	return pp
}

func (pp primitiveParams) WithKey(key []byte) primitiveParams {
	pp.Key = key
	return pp
}

func getKey(t *testing.T, params primitiveParams) []byte {
	ms := &clpb.CLMasterSecret{
		Version:  params.Version,
		KeyValue: params.Key,
	}
	msKeyProto, err := proto.Marshal(ms)
	require.NoError(t, err)
	return msKeyProto
}

func getSerializedKeyFormat(t *testing.T, params primitiveParams) []byte {
	keyFormat := &clpb.CLMasterSecretKeyFormat{}
	keyFormatProto, err := proto.Marshal(keyFormat)
	require.NoError(t, err)
	return keyFormatProto
}
