/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/square/go-jose/v3/json"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func getTestKeyResolver(pubKey *verifier.PublicKey, err error) KeyResolver {
	return KeyResolverFunc(func(string, string) (*verifier.PublicKey, error) {
		return pubKey, err
	})
}

func TestNewVerifier(t *testing.T) {
	r := require.New(t)

	t.Run("Verify JWT signed by EdDSA", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		signer := newEd25519Signer(privKey)

		token, err := NewSigned(&Claims{Issuer: "Mike"}, nil, signer)
		r.NoError(err)
		jws, err := token.Serialize(false)
		r.NoError(err)

		v := NewVerifier(getTestKeyResolver(
			&verifier.PublicKey{
				Type:  kms.Ed25519Type,
				Value: pubKey,
			}, nil))
		_, err = jose.ParseJWS(jws, v)
		r.NoError(err)
	})

	t.Run("Verify JWT signed by RS256", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		r.NoError(err)

		pubKey := &privKey.PublicKey

		signer := newRS256Signer(privKey, nil)

		token, err := NewSigned(&Claims{Issuer: "Mike"}, nil, signer)
		r.NoError(err)
		jws, err := token.Serialize(false)
		r.NoError(err)

		v := NewVerifier(getTestKeyResolver(
			&verifier.PublicKey{
				Type:  "RSA",
				Value: x509.MarshalPKCS1PublicKey(pubKey),
			}, nil))
		_, err = jose.ParseJWS(jws, v)
		r.NoError(err)
	})
}

func TestBasicVerifier_Verify(t *testing.T) { // error corner cases
	r := require.New(t)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	v := NewVerifier(getTestKeyResolver(&verifier.PublicKey{
		Type:  "RSA",
		Value: pubKey,
	}, nil))

	validHeaders := map[string]interface{}{
		"alg": "EdDSA",
	}

	// Invalid claims
	err = v.Verify(validHeaders, []byte("invalid JSON claims"), nil, nil)
	r.Error(err)
	r.Contains(err.Error(), "read claims from JSON Web Token")

	// Issuer claim is not defined
	claimsWithoutIssuer, err := json.Marshal(map[string]interface{}{})
	r.NoError(err)
	err = v.Verify(validHeaders, claimsWithoutIssuer, nil, nil)
	r.Error(err)
	r.Contains(err.Error(), "issuer claim is not defined")

	// Issuer claim is not a string
	claimsWithInvalidIssuer, err := json.Marshal(map[string]interface{}{"iss": 444})
	r.NoError(err)
	err = v.Verify(validHeaders, claimsWithInvalidIssuer, nil, nil)
	r.Error(err)
	r.Contains(err.Error(), "issuer claim is not a string")

	validClaims, err := json.Marshal(map[string]interface{}{"iss": "Bob"})
	r.NoError(err)

	// key resolver error
	v = NewVerifier(getTestKeyResolver(nil, errors.New("failed to resolve public key")))
	err = v.Verify(validHeaders, validClaims, nil, nil)
	r.Error(err)
	r.Contains(err.Error(), "failed to resolve public key")
}

func TestVerifyEdDSA(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	signature := ed25519.Sign(privKey, []byte("test message"))

	err = VerifyEdDSA(&verifier.PublicKey{
		Type:  kms.Ed25519Type,
		Value: pubKey,
	}, []byte("test message"), signature)
	r.NoError(err)

	err = VerifyEdDSA(&verifier.PublicKey{
		Type:  kms.Ed25519Type,
		Value: []byte("invalid pub key"),
	}, []byte("test message"), signature)
	r.Error(err)
	r.EqualError(err, "bad ed25519 public key length")

	anotherPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	err = VerifyEdDSA(&verifier.PublicKey{
		Type:  kms.Ed25519Type,
		Value: anotherPubKey,
	}, []byte("test message"), signature)
	r.Error(err)
	r.EqualError(err, "signature doesn't match")
}

func TestVerifyRS256(t *testing.T) {
	r := require.New(t)

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	r.NoError(err)

	hash := crypto.SHA256.New()

	_, err = hash.Write([]byte("test message"))
	r.NoError(err)

	hashed := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed)
	r.NoError(err)

	err = VerifyRS256(&verifier.PublicKey{
		Type:  "RSA",
		Value: x509.MarshalPKCS1PublicKey(&privKey.PublicKey),
	}, []byte("test message"), signature)
	r.NoError(err)

	anotherPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	r.NoError(err)

	err = VerifyRS256(&verifier.PublicKey{
		Type:  "RSA",
		Value: x509.MarshalPKCS1PublicKey(&anotherPrivKey.PublicKey),
	}, []byte("test message"), signature)
	r.Error(err)
}
