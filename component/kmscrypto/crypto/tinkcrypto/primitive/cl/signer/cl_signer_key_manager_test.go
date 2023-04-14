//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	clsubtle "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/subtle"
	clpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/cl_go_proto"
)

func TestCLSignerKeyManager_Primitive(t *testing.T) {
	km := newCLSignerKeyManager()

	t.Run("Test signer key manager Primitive() success", func(t *testing.T) {
		p, err := km.Primitive(getKey(t, validPrimitiveParams(t)))
		require.NoError(t, err)
		require.NotEmpty(t, p)
	})

	t.Run("Test signer key manager Primitive() with empty serialized key", func(t *testing.T) {
		p, err := km.Primitive([]byte(""))
		require.EqualError(t, err, errInvalidCLSignerKey.Error(),
			"clSignerKeyManager primitive from empty serialized key must fail")
		require.Empty(t, p)
	})

	t.Run("Test signer key manager Primitive() with bad serialize key", func(t *testing.T) {
		p, err := km.Primitive([]byte("bad.data"))
		require.Contains(t, err.Error(), errInvalidCLSignerKey.Error())
		require.Contains(t, err.Error(), "invalid proto: proto:")
		require.Contains(t, err.Error(), "cannot parse invalid wire-format data")
		require.Empty(t, p)
	})

	t.Run("Test signer key manager Primitive() with bad version key", func(t *testing.T) {
		p, err := km.Primitive(
			getKey(t,
				validPrimitiveParams(t).WithVersion(uint32(999)),
			),
		)
		require.Contains(t, err.Error(), errInvalidCLSignerKey.Error())
		require.Contains(t, err.Error(), "invalid key version")
		require.Empty(t, p)
	})

	t.Run("Test signer key manager Primitive() with empty attrs", func(t *testing.T) {
		p, err := km.Primitive(
			getKey(t,
				validPrimitiveParams(t).WithAttrs([]string{}),
			),
		)
		require.Contains(t, err.Error(), errInvalidCLSignerKey.Error())
		require.Contains(t, err.Error(), "empty attributes")
		require.Empty(t, p)
	})

	t.Run("Test signer key manager Primitive() with invalid ursa private keys", func(t *testing.T) {
		p, err := km.Primitive(
			getKey(t,
				validPrimitiveParams(t).WithPrivKey([]byte("bad data")),
			),
		)
		require.Contains(t, err.Error(), errInvalidCLSignerKey.Error())
		require.Contains(t, err.Error(), "invalid ursa key")
		require.Contains(t, err.Error(), "invalid cred def private key")
		require.Empty(t, p)
	})

	t.Run("Test signer key manager Primitive() with invalid ursa public keys", func(t *testing.T) {
		p, err := km.Primitive(
			getKey(t,
				validPrimitiveParams(t).WithPubKey([]byte("bad data")),
			),
		)
		require.Contains(t, err.Error(), errInvalidCLSignerKey.Error())
		require.Contains(t, err.Error(), "invalid ursa key")
		require.Contains(t, err.Error(), "invalid cred def public key")
		require.Empty(t, p)
	})

	t.Run("Test signer key manager Primitive() with invalid ursa key proof", func(t *testing.T) {
		p, err := km.Primitive(
			getKey(t,
				validPrimitiveParams(t).WithCorrectnessProof([]byte("bad data")),
			),
		)
		require.Contains(t, err.Error(), errInvalidCLSignerKey.Error())
		require.Contains(t, err.Error(), "invalid ursa key")
		require.Contains(t, err.Error(), "invalid cred def correctness proof")
		require.Empty(t, p)
	})
}

func TestCLSignerKeyManager_NewKey(t *testing.T) {
	km := newCLSignerKeyManager()

	t.Run("Test signer key manager NewKey() success", func(t *testing.T) {
		p, err := km.NewKey(getSerializedKeyFormat(t, validPrimitiveParams(t)))
		require.NoError(t, err)
		require.NotEmpty(t, p)
	})

	t.Run("Test signer key manager NewKey() with nil key", func(t *testing.T) {
		k, err := km.NewKey(nil)
		require.EqualError(t, err, errInvalidCLSignerKeyFormat.Error())
		require.Empty(t, k)
	})

	t.Run("Test signer key manager NewKey() with bad serialize key", func(t *testing.T) {
		p, err := km.NewKey([]byte("bad.data"))
		require.Contains(t, err.Error(), errInvalidCLSignerKeyFormat.Error())
		require.Contains(t, err.Error(), "invalid proto: proto:")
		require.Contains(t, err.Error(), "cannot parse invalid wire-format data")
		require.Empty(t, p)
	})

	t.Run("Test signer key manager NewKey() with empty attrs", func(t *testing.T) {
		p, err := km.NewKey(
			getSerializedKeyFormat(t,
				validPrimitiveParams(t).WithAttrs([]string{}),
			),
		)
		require.Contains(t, err.Error(), errInvalidCLSignerKey.Error())
		require.Contains(t, err.Error(), "empty attributes")
		require.Empty(t, p)
	})
}

func TestCLSignerKeyManager_NewKeyData(t *testing.T) {
	km := newCLSignerKeyManager()

	t.Run("Test signer key manager NewKeyData() success", func(t *testing.T) {
		p, err := km.NewKeyData(getSerializedKeyFormat(t, validPrimitiveParams(t)))
		require.NoError(t, err)
		require.NotEmpty(t, p)
	})

	t.Run("Test signer key manager NewKeyData() with nil key", func(t *testing.T) {
		k, err := km.NewKeyData(nil)
		require.EqualError(t, err, errInvalidCLSignerKeyFormat.Error())
		require.Empty(t, k)
	})

	t.Run("Test signer key manager NewKeyData() with bad serialize key", func(t *testing.T) {
		p, err := km.NewKeyData([]byte("bad.data"))
		require.Contains(t, err.Error(), errInvalidCLSignerKeyFormat.Error())
		require.Contains(t, err.Error(), "invalid proto: proto:")
		require.Contains(t, err.Error(), "cannot parse invalid wire-format data")
		require.Empty(t, p)
	})

	t.Run("Test signer key manager NewKeyData() with empty attrs", func(t *testing.T) {
		p, err := km.NewKeyData(
			getSerializedKeyFormat(t,
				validPrimitiveParams(t).WithAttrs([]string{}),
			),
		)
		require.Contains(t, err.Error(), errInvalidCLSignerKey.Error())
		require.Contains(t, err.Error(), "empty attributes")
		require.Empty(t, p)
	})
}

func TestCLSignerKeyManager_DoesSupport(t *testing.T) {
	km := newCLSignerKeyManager()
	require.False(t, km.DoesSupport("bad/url"))
	require.True(t, km.DoesSupport(clSignerKeyTypeURL))
}

func TestCLSignertKeyManager_TypeURL(t *testing.T) {
	km := newCLSignerKeyManager()
	require.Equal(t, clSignerKeyTypeURL, km.TypeURL())
}

type primitiveParams struct {
	Version          uint32
	Attrs            []string
	PrivKey          []byte
	PubKey           []byte
	CorrectnessProof []byte
}

func validPrimitiveParams(t *testing.T) *primitiveParams {
	validVersion := uint32(0)
	validPrivKey, validPubKey, proof, validAttrs := clsubtle.CreateCredentialDefinitionJSON(t)

	return &primitiveParams{
		Version:          validVersion,
		Attrs:            validAttrs,
		PrivKey:          validPrivKey,
		PubKey:           validPubKey,
		CorrectnessProof: proof,
	}
}

func (pp *primitiveParams) WithVersion(version uint32) *primitiveParams {
	pp.Version = version
	return pp
}

func (pp *primitiveParams) WithAttrs(attrs []string) *primitiveParams {
	pp.Attrs = attrs
	return pp
}

func (pp *primitiveParams) WithPrivKey(privKey []byte) *primitiveParams {
	pp.PrivKey = privKey
	return pp
}

func (pp *primitiveParams) WithPubKey(pubKey []byte) *primitiveParams {
	pp.PubKey = pubKey
	return pp
}

func (pp *primitiveParams) WithCorrectnessProof(proof []byte) *primitiveParams {
	pp.CorrectnessProof = proof
	return pp
}

func getKey(t *testing.T, params *primitiveParams) []byte {
	privKey := &clpb.CLCredDefPrivateKey{
		Version:  params.Version,
		KeyValue: params.PrivKey,
		PublicKey: &clpb.CLCredDefPublicKey{
			Version: params.Version,
			Params: &clpb.CLCredDefParams{
				Attrs: params.Attrs,
			},
			KeyValue:            params.PubKey,
			KeyCorrectnessProof: params.CorrectnessProof,
		},
	}
	privKeyProto, err := proto.Marshal(privKey)
	require.NoError(t, err)

	return privKeyProto
}

func getSerializedKeyFormat(t *testing.T, params *primitiveParams) []byte {
	keyFormat := &clpb.CLCredDefKeyFormat{
		Params: &clpb.CLCredDefParams{
			Attrs: params.Attrs,
		},
	}
	keyFormatProto, err := proto.Marshal(keyFormat)
	require.NoError(t, err)

	return keyFormatProto
}
