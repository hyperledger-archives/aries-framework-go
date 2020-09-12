/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	gojose "github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	kmsapi "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
)

func TestNewPublicKeyVerifier(t *testing.T) {
	var (
		publicKey = &PublicKey{
			Type: "TestType",
			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Algorithm: "alg",
				},
				Kty: "kty",
				Crv: "crv",
			},
		}

		msg    = []byte("message to sign")
		msgSig = []byte("signature")

		signatureVerifier = &testSignatureVerifier{
			baseSignatureVerifier: baseSignatureVerifier{
				keyType:   "kty",
				curve:     "crv",
				algorithm: "alg",
			},
			verifyResult: nil,
		}
	)

	verifier := NewPublicKeyVerifier(signatureVerifier, WithExactPublicKeyType("TestType"))
	require.NotNil(t, verifier)

	err := verifier.Verify(publicKey, msg, msgSig)
	require.NoError(t, err)

	t.Run("check public key type", func(t *testing.T) {
		publicKey.Type = "invalid TestType"

		err = verifier.Verify(publicKey, msg, msgSig)
		require.Error(t, err)
		require.EqualError(t, err, "a type of public key is not 'TestType'")

		publicKey.Type = "TestType"
	})

	t.Run("match JWK key type", func(t *testing.T) {
		publicKey.JWK.Kty = "invalid kty"

		err = verifier.Verify(publicKey, msg, msgSig)
		require.Error(t, err)
		require.EqualError(t, err, "verifier does not match JSON Web Key")

		publicKey.JWK.Kty = "kty"
	})

	t.Run("match JWK curve", func(t *testing.T) {
		publicKey.JWK.Crv = "invalid crv"

		err = verifier.Verify(publicKey, msg, msgSig)
		require.Error(t, err)
		require.EqualError(t, err, "verifier does not match JSON Web Key")

		publicKey.JWK.Crv = "crv"
	})

	t.Run("match JWK algorithm", func(t *testing.T) {
		publicKey.JWK.Algorithm = "invalid alg"

		err = verifier.Verify(publicKey, msg, msgSig)
		require.Error(t, err)
		require.EqualError(t, err, "verifier does not match JSON Web Key")

		publicKey.JWK.Algorithm = "alg"
	})

	signatureVerifier.verifyResult = errors.New("invalid signature")
	err = verifier.Verify(publicKey, msg, msgSig)
	require.Error(t, err)
	require.EqualError(t, err, "invalid signature")
}

func TestNewCompositePublicKeyVerifier(t *testing.T) {
	var (
		publicKey = &PublicKey{
			Type: "TestType",
			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Algorithm: "alg",
				},
				Kty: "kty",
				Crv: "crv",
			},
		}

		msg    = []byte("message to sign")
		msgSig = []byte("signature")

		signatureVerifier = &testSignatureVerifier{
			baseSignatureVerifier: baseSignatureVerifier{
				keyType:   "kty",
				curve:     "crv",
				algorithm: "alg",
			},
			verifyResult: nil,
		}
	)

	verifier := NewCompositePublicKeyVerifier([]SignatureVerifier{signatureVerifier},
		WithExactPublicKeyType("TestType"))
	require.NotNil(t, verifier)

	err := verifier.Verify(publicKey, msg, msgSig)
	require.NoError(t, err)

	publicKey.JWK.Kty = "invalid kty"
	err = verifier.Verify(publicKey, msg, msgSig)
	require.Error(t, err)
	require.EqualError(t, err, "no matching verifier found")

	publicKey.JWK.Kty = "kty"

	signatureVerifier.verifyResult = errors.New("invalid signature")
	err = verifier.Verify(publicKey, msg, msgSig)
	require.Error(t, err)
	require.EqualError(t, err, "invalid signature")
}

func TestNewEd25519SignatureVerifier(t *testing.T) {
	v := NewEd25519SignatureVerifier()
	require.NotNil(t, v)

	signer, err := newCryptoSigner(kmsapi.ED25519Type)
	require.NoError(t, err)

	msg := []byte("test message")
	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	pubKey := &PublicKey{
		Type:  kmsapi.ED25519,
		Value: signer.PublicKeyBytes(),
	}

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)

	// invalid public key type
	err = v.Verify(&PublicKey{
		Type:  kmsapi.ED25519,
		Value: []byte("invalid-key"),
	}, msg, msgSig)
	require.Error(t, err)
	require.EqualError(t, err, "ed25519: invalid key")

	// invalid signature
	err = v.Verify(pubKey, msg, []byte("invalid signature"))
	require.Error(t, err)
	require.EqualError(t, err, "ed25519: invalid signature")
}

func TestNewRSAPS256SignatureVerifier(t *testing.T) {
	v := NewRSAPS256SignatureVerifier()
	require.NotNil(t, v)

	signer, err := newCryptoSigner(kmsapi.RSAPS256Type)
	require.NoError(t, err)

	msg := []byte("test message")

	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	pubKey := &PublicKey{
		Type: "JwsVerificationKey2020",
		JWK: &jose.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Algorithm: "PS256",
			},
			Kty: "RSA",
		},
		Value: signer.PublicKeyBytes(),
	}

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)

	// invalid signature
	err = v.Verify(pubKey, msg, []byte("invalid signature"))
	require.Error(t, err)
	require.EqualError(t, err, "rsa: invalid signature")

	// invalid public key
	pubKey.Value = []byte("invalid-key")
	err = v.Verify(pubKey, msg, msgSig)
	require.Error(t, err)
	require.EqualError(t, err, "rsa: invalid public key")
}

func TestNewECDSAES256SignatureVerifier(t *testing.T) {
	msg := []byte("test message")

	t.Run("happy path", func(t *testing.T) {
		tests := []struct {
			sVerifier SignatureVerifier
			curve     elliptic.Curve
			curveName string
			algorithm string
			hash      crypto.Hash
		}{
			{
				sVerifier: NewECDSAES256SignatureVerifier(),
				curve:     elliptic.P256(),
				curveName: "P-256",
				algorithm: "ES256",
				hash:      crypto.SHA256,
			},
			{
				sVerifier: NewECDSAES384SignatureVerifier(),
				curve:     elliptic.P384(),
				curveName: "P-384",
				algorithm: "ES384",
				hash:      crypto.SHA384,
			},
			{
				sVerifier: NewECDSAES521SignatureVerifier(),
				curve:     elliptic.P521(),
				curveName: "P-521",
				algorithm: "ES521",
				hash:      crypto.SHA512,
			},
			{
				sVerifier: NewECDSASecp256k1SignatureVerifier(),
				curve:     btcec.S256(),
				curveName: "secp256k1",
				algorithm: "ES256K",
				hash:      crypto.SHA256,
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.curveName, func(t *testing.T) {
				keyType, err := signature.MapECCurveToKeyType(tc.curve)
				require.NoError(t, err)

				signer, err := newCryptoSigner(keyType)
				require.NoError(t, err)

				pubKey := &PublicKey{
					Type:  "JwsVerificationKey2020",
					Value: signer.PublicKeyBytes(),
					JWK: &jose.JWK{
						JSONWebKey: gojose.JSONWebKey{
							Algorithm: tc.algorithm,
							Key:       signer.PublicKey(),
						},
						Crv: tc.curveName,
						Kty: "EC",
					},
				}

				msgSig, err := signer.Sign(msg)
				require.NoError(t, err)

				err = tc.sVerifier.Verify(pubKey, msg, msgSig)
				require.NoError(t, err)
			})
		}
	})

	v := NewECDSAES256SignatureVerifier()
	require.NotNil(t, v)

	signer, err := newCryptoSigner(kmsapi.ECDSAP256TypeIEEEP1363)
	require.NoError(t, err)
	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	t.Run("verify with public key bytes", func(t *testing.T) {
		verifyError := v.Verify(&PublicKey{
			Type:  "JwsVerificationKey2020",
			Value: signer.PublicKeyBytes(),
		}, msg, msgSig)

		require.NoError(t, verifyError)
	})

	t.Run("invalid public key", func(t *testing.T) {
		verifyError := v.Verify(&PublicKey{
			Type:  "JwsVerificationKey2020",
			Value: []byte("invalid public key"),
		}, msg, msgSig)

		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: create JWK from public key bytes: invalid public key")
	})

	t.Run("invalid public key type", func(t *testing.T) {
		ed25519Key := &ed25519.PublicKey{}

		verifyError := v.Verify(&PublicKey{
			Type:  "JwsVerificationKey2020",
			Value: signer.PublicKeyBytes(),
			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Algorithm: "ES256",
					Key:       ed25519Key,
				},
				Crv: "P-256",
				Kty: "EC",
			},
		}, msg, msgSig)
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: invalid public key type")
	})

	t.Run("invalid signature", func(t *testing.T) {
		pubKey := &PublicKey{
			Type:  "JwsVerificationKey2020",
			Value: signer.PublicKeyBytes(),

			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Algorithm: "ES256",
					Key:       signer.PublicKey(),
				},
				Crv: "P-256",
				Kty: "EC",
			},
		}

		verifyError := v.Verify(pubKey, msg, []byte("signature of invalid size"))
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: invalid signature size")

		emptySig := make([]byte, 64)
		verifyError = v.Verify(pubKey, msg, emptySig)
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: invalid signature")
	})
}

type testSignatureVerifier struct {
	baseSignatureVerifier

	verifyResult error
}

func (v testSignatureVerifier) Verify(*PublicKey, []byte, []byte) error {
	return v.verifyResult
}

func newCryptoSigner(keyType kmsapi.KeyType) (signature.Signer, error) {
	p := mockkms.NewProviderForKMS(storage.NewMockStoreProvider(), &noop.NoLock{})
	localKMS, err := localkms.New("local-lock://custom/main/key/", p)
	if err != nil {
		return nil, err
	}

	tinkCrypto, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	return signature.NewCryptoSigner(tinkCrypto, localKMS, keyType)
}
