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
	"errors"
	"testing"

	"github.com/square/go-jose/v3/json"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
)

func getTestKeyResolver(pubKey interface{}, err error) KeyResolver {
	return KeyResolverFunc(func(string, string) (interface{}, error) {
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

		verifier := NewVerifier(getTestKeyResolver(pubKey, nil))
		_, err = jose.ParseJWS(jws, verifier)
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

		verifier := NewVerifier(getTestKeyResolver(pubKey, nil))
		_, err = jose.ParseJWS(jws, verifier)
		r.NoError(err)
	})
}

func TestBasicVerifier_Verify(t *testing.T) { // error corner cases
	r := require.New(t)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	verifier := NewVerifier(getTestKeyResolver(pubKey, nil))

	validHeaders := map[string]interface{}{
		"alg": "EdDSA",
	}

	// Invalid claims
	err = verifier.Verify(validHeaders, []byte("invalid JSON claims"), nil, nil)
	r.Error(err)
	r.Contains(err.Error(), "read claims from JSON Web Token")

	// Issuer claim is not defined
	claimsWithoutIssuer, err := json.Marshal(map[string]interface{}{})
	r.NoError(err)
	err = verifier.Verify(validHeaders, claimsWithoutIssuer, nil, nil)
	r.Error(err)
	r.Contains(err.Error(), "issuer claim is not defined")

	// Issuer claim is not a string
	claimsWithInvalidIssuer, err := json.Marshal(map[string]interface{}{"iss": 444})
	r.NoError(err)
	err = verifier.Verify(validHeaders, claimsWithInvalidIssuer, nil, nil)
	r.Error(err)
	r.Contains(err.Error(), "issuer claim is not a string")

	validClaims, err := json.Marshal(map[string]interface{}{"iss": "Bob"})
	r.NoError(err)

	// key resolver error
	verifier = NewVerifier(getTestKeyResolver(nil, errors.New("failed to resolve public key")))
	err = verifier.Verify(validHeaders, validClaims, nil, nil)
	r.Error(err)
	r.Contains(err.Error(), "failed to resolve public key")
}

func TestVerifyEdDSA(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	signature := ed25519.Sign(privKey, []byte("test message"))

	err = VerifyEdDSA(pubKey, []byte("test message"), signature)
	r.NoError(err)

	err = VerifyEdDSA([]byte("invalid pub key"), []byte("test message"), signature)
	r.Error(err)
	r.EqualError(err, "bad ed25519 public key length")

	anotherPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	err = VerifyEdDSA(anotherPubKey, []byte("test message"), signature)
	r.Error(err)
	r.EqualError(err, "signature doesn't match")

	err = VerifyEdDSA("not EdDSA public key", []byte("test message"), signature)
	r.Error(err)
	r.EqualError(err, "not []byte or ed25519.PublicKey public key")
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

	err = VerifyRS256(&privKey.PublicKey, []byte("test message"), signature)
	r.NoError(err)

	anotherPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	r.NoError(err)

	err = VerifyRS256(&anotherPrivKey.PublicKey, []byte("test message"), signature)
	r.Error(err)

	err = VerifyRS256("not RS256 public key", []byte("test message"), signature)
	r.Error(err)
	r.EqualError(err, "not *rsa.PublicKey public key")
}
