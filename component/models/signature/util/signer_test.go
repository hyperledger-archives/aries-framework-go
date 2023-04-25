/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"

	"github.com/hyperledger/aries-framework-go/component/models/signature/util/internal/signer"
)

func TestNewCryptoSigner(t *testing.T) {
	p, err := mockkms.NewProviderForKMS(storage.NewMockStoreProvider(), &noop.NoLock{})
	require.NoError(t, err)

	localKMS, err := localkms.New("local-lock://custom/master/key/", p)
	require.NoError(t, err)

	tinkCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	for _, keyType := range [...]kmsapi.KeyType{
		kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP521TypeDER,
		kmsapi.ECDSAP256TypeIEEEP1363, kmsapi.ECDSAP521TypeIEEEP1363, kmsapi.ED25519Type,
		kmsapi.ECDSAP384TypeIEEEP1363, kmsapi.ECDSASecp256k1TypeIEEEP1363, kmsapi.RSARS256Type, kmsapi.RSAPS256Type,
	} {
		newSigner, signerErr := NewCryptoSigner(tinkCrypto, localKMS, keyType)
		require.NoError(t, signerErr)

		msgSig, signerErr := newSigner.Sign([]byte("test message"))
		require.NoError(t, signerErr)
		require.NotEmpty(t, msgSig)
	}

	newSigner, err := NewCryptoSigner(tinkCrypto, localKMS, kmsapi.ChaCha20Poly1305Type)
	require.Error(t, err)
	require.EqualError(t, err, "unsupported key type")
	require.Nil(t, newSigner)
}

func TestNewSigner(t *testing.T) {
	for _, keyType := range [...]kmsapi.KeyType{
		kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP521TypeDER,
		kmsapi.ECDSAP256TypeIEEEP1363, kmsapi.ECDSAP521TypeIEEEP1363, kmsapi.ED25519Type,
		kmsapi.ECDSAP384TypeIEEEP1363, kmsapi.ECDSASecp256k1TypeIEEEP1363, kmsapi.RSARS256Type, kmsapi.RSAPS256Type,
	} {
		newSigner, signerErr := NewSigner(keyType)
		require.NoError(t, signerErr)

		msgSig, signerErr := newSigner.Sign([]byte("test message"))
		require.NoError(t, signerErr)
		require.NotEmpty(t, msgSig)
	}

	invalidSigner, err := NewSigner(kmsapi.ChaCha20Poly1305Type)
	require.Error(t, err)
	require.EqualError(t, err, "unsupported key type")
	require.Nil(t, invalidSigner)
}

func TestGetEd25519Signer(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	ed25519Signer := GetEd25519Signer(privKey, pubKey)
	require.NotNil(t, ed25519Signer)
	require.IsType(t, &signer.Ed25519Signer{}, ed25519Signer)
}

func TestGetSigner(t *testing.T) {
	type args struct {
		privateKeyGetter func() (interface{}, error)
	}

	tests := []struct {
		name       string
		args       args
		wantGetter func(privateKey interface{}) Signer
		wantErr    bool
	}{
		{
			name: "ECDSA_P256",
			args: args{
				privateKeyGetter: func() (interface{}, error) {
					return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				},
			},
			wantGetter: func(privateKey interface{}) Signer {
				return signer.GetECDSAP256Signer(privateKey.(*ecdsa.PrivateKey))
			},
			wantErr: false,
		},
		{
			name: "ECDSA_P384",
			args: args{
				privateKeyGetter: func() (interface{}, error) {
					return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				},
			},
			wantGetter: func(privateKey interface{}) Signer {
				return signer.GetECDSAP384Signer(privateKey.(*ecdsa.PrivateKey))
			},
			wantErr: false,
		},
		{
			name: "ECDSA_P521",
			args: args{
				privateKeyGetter: func() (interface{}, error) {
					return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				},
			},
			wantGetter: func(privateKey interface{}) Signer {
				return signer.GetECDSAP521Signer(privateKey.(*ecdsa.PrivateKey))
			},
			wantErr: false,
		},
		{
			name: "ECDSA_Secp256k1",
			args: args{
				privateKeyGetter: func() (interface{}, error) {
					return ecdsa.GenerateKey(btcec.S256(), rand.Reader)
				},
			},
			wantGetter: func(privateKey interface{}) Signer {
				return signer.GetECDSASecp256k1Signer(privateKey.(*ecdsa.PrivateKey))
			},
			wantErr: false,
		},
		{
			name: "Ed25519",
			args: args{
				privateKeyGetter: func() (interface{}, error) {
					_, privateKey, err := ed25519.GenerateKey(rand.Reader)
					return privateKey, err
				},
			},
			wantGetter: func(privateKey interface{}) Signer {
				return signer.GetEd25519Signer(privateKey.(ed25519.PrivateKey), nil)
			},
			wantErr: false,
		},
		{
			name: "RSA_PS256",
			args: args{
				privateKeyGetter: func() (interface{}, error) {
					return rsa.GenerateKey(rand.Reader, 2048)
				},
			},
			wantGetter: func(privateKey interface{}) Signer {
				return signer.GetPS256Signer(privateKey.(*rsa.PrivateKey))
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := tt.args.privateKeyGetter()
			if err != nil {
				t.Errorf("privateKeyGetter() error = %v", err)
				return
			}
			privateKeyJWK := &jwk.JWK{
				JSONWebKey: jose.JSONWebKey{Key: privateKey},
			}
			got, err := GetSigner(privateKeyJWK)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			want := tt.wantGetter(privateKey)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("GetSigner() got = %v, want %v", got, want)
			}
		})
	}
}
