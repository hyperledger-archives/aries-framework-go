//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blinder

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	clsubtle "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/subtle"
	clpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/cl_go_proto"
)

func TestCLBlinderKeyManager_Primitive(t *testing.T) {
	km := newCLBlinderKeyManager()

	t.Run("Test blinder key manager Primitive() success", func(t *testing.T) {
		p, err := km.Primitive(getKey(t, validPrimitiveParams(t)))
		require.NoError(t, err)
		require.NotEmpty(t, p)
	})

	t.Run("Test blinder key manager Primitive() with nil serialized key", func(t *testing.T) {
		p, err := km.Primitive(nil)
		require.Contains(t, err.Error(), errInvalidCLBlinderKey.Error())
		require.Empty(t, p)
	})

	t.Run("Test blinder key manager Primitive() with bad serialize key", func(t *testing.T) {
		p, err := km.Primitive([]byte("bad.data"))
		require.Contains(t, err.Error(), errInvalidCLBlinderKey.Error())
		require.Contains(t, err.Error(), "invalid proto: proto:")
		require.Contains(t, err.Error(), "cannot parse invalid wire-format data")
		require.Empty(t, p)
	})

	t.Run("Test blinder key manager Primitive() with bad version key", func(t *testing.T) {
		p, err := km.Primitive(
			getKey(t,
				validPrimitiveParams(t).WithVersion(uint32(999)),
			),
		)
		require.Contains(t, err.Error(), errInvalidCLBlinderKey.Error())
		require.Contains(t, err.Error(), "invalid key version")
		require.Empty(t, p)
	})

	t.Run("Test blinder key manager Primitive() with invalid ursa key", func(t *testing.T) {
		p, err := km.Primitive(
			getKey(t,
				validPrimitiveParams(t).WithKey([]byte("bad data")),
			),
		)
		require.Contains(t, err.Error(), errInvalidCLBlinderKey.Error())
		require.Contains(t, err.Error(), "invalid ursa key")
		require.Contains(t, err.Error(), "invalid master secret key")
		require.Empty(t, p)
	})
}

func TestCLBlinderKeyManager_NewKey(t *testing.T) {
	km := newCLBlinderKeyManager()

	t.Run("Test blinder key manager NewKey() success", func(t *testing.T) {
		p, err := km.NewKey(getSerializedKeyFormat(t, validPrimitiveParams(t)))
		require.NoError(t, err)
		require.NotEmpty(t, p)
	})

	t.Run("Test blinder key manager NewKey() with nil key", func(t *testing.T) {
		k, err := km.NewKey(nil)
		require.EqualError(t, err, errInvalidCLBlinderKeyFormat.Error())
		require.Empty(t, k)
	})

	t.Run("Test blinder key manager NewKey() with bad serialize key", func(t *testing.T) {
		p, err := km.NewKey([]byte("bad.data"))
		require.Contains(t, err.Error(), errInvalidCLBlinderKeyFormat.Error())
		require.Contains(t, err.Error(), "invalid proto: proto:")
		require.Contains(t, err.Error(), "cannot parse invalid wire-format data")
		require.Empty(t, p)
	})
}

func TestCLBlinderKeyManager_NewKeyData(t *testing.T) {
	km := newCLBlinderKeyManager()

	t.Run("Test blinder key manager NewKeyData() success", func(t *testing.T) {
		p, err := km.NewKeyData(getSerializedKeyFormat(t, validPrimitiveParams(t)))
		require.NoError(t, err)
		require.NotEmpty(t, p)
	})

	t.Run("Test blinder key manager NewKeyData() with nil key", func(t *testing.T) {
		k, err := km.NewKeyData(nil)
		require.EqualError(t, err, errInvalidCLBlinderKeyFormat.Error())
		require.Empty(t, k)
	})

	t.Run("Test blinder key manager NewKeyData() with bad serialize key", func(t *testing.T) {
		p, err := km.NewKeyData([]byte("bad.data"))
		require.Contains(t, err.Error(), errInvalidCLBlinderKeyFormat.Error())
		require.Contains(t, err.Error(), "invalid proto: proto:")
		require.Contains(t, err.Error(), "cannot parse invalid wire-format data")
		require.Empty(t, p)
	})
}

func TestCLBlinderKeyManager_DoesSupport(t *testing.T) {
	km := newCLBlinderKeyManager()
	require.False(t, km.DoesSupport("bad/url"))
	require.True(t, km.DoesSupport(clBlinderKeyTypeURL))
}

func TestCLBlinderKeyManager_TypeURL(t *testing.T) {
	km := newCLBlinderKeyManager()
	require.Equal(t, clBlinderKeyTypeURL, km.TypeURL())
}

type primitiveParams struct {
	Version uint32
	Key     []byte
}

func validPrimitiveParams(t *testing.T) primitiveParams {
	validVersion := uint32(0)
	validKey := clsubtle.CreateMasterSecretKeyJSON(t)

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

// nolint:unparam
func getSerializedKeyFormat(t *testing.T, params primitiveParams) []byte {
	keyFormat := &clpb.CLMasterSecretKeyFormat{}
	keyFormatProto, err := proto.Marshal(keyFormat)
	require.NoError(t, err)

	return keyFormatProto
}
