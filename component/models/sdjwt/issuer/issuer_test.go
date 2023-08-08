/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PaesslerAG/jsonpath"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/json"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	afjose "github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"

	afjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
)

const (
	issuer                 = "https://example.com/issuer"
	expectedHashWithSpaces = "qqvcqnczAMgYx7EykI6wwtspyvyvK790ge7MBbQ-Nus"
	sampleSalt             = "3jqcb67z9wks08zwiK7EyQ"
)

func TestNew(t *testing.T) {
	claims := createClaims()

	t.Run("Create SD-JWT without signing", func(t *testing.T) {
		r := require.New(t)

		token, err := New(issuer, claims, nil, &unsecuredJWTSigner{})
		r.NoError(err)
		combinedFormatForIssuance, err := token.Serialize(false)
		require.NoError(t, err)

		cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)
		require.Equal(t, 1, len(cfi.Disclosures))

		var payload map[string]interface{}
		err = token.DecodeClaims(&payload)
		r.NoError(err)

		r.Len(payload[common.SDKey], 1)
		r.Equal("sha-256", payload[common.SDAlgorithmKey])
		r.Equal(issuer, payload["iss"])
	})

	t.Run("Create JWS signed by EdDSA", func(t *testing.T) {
		r := require.New(t)

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		token, err := New(issuer, claims, nil, afjwt.NewEd25519Signer(privKey),
			WithJSONMarshaller(jsonMarshalWithSpace),
			WithSaltFnc(func() (string, error) {
				return sampleSalt, nil
			}))
		r.NoError(err)
		combinedFormatForIssuance, err := token.Serialize(false)
		require.NoError(t, err)

		fmt.Printf(combinedFormatForIssuance)

		cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)
		require.Equal(t, 1, len(cfi.Disclosures))

		var parsedClaims map[string]interface{}
		err = verifyEd25519ViaGoJose(cfi.SDJWT, pubKey, &parsedClaims)
		r.NoError(err)

		parsedClaimsBytes, err := json.Marshal(parsedClaims)
		require.NoError(t, err)

		prettyJSON, err := prettyPrint(parsedClaimsBytes)
		require.NoError(t, err)

		fmt.Println(prettyJSON)

		require.True(t, existsInDisclosures(parsedClaims, expectedHashWithSpaces))

		err = verifyEd25519(cfi.SDJWT, pubKey)
		r.NoError(err)
	})

	t.Run("Create JWS signed by RS256", func(t *testing.T) {
		r := require.New(t)

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		r.NoError(err)

		pubKey := &privKey.PublicKey

		token, err := New(issuer, claims, nil, afjwt.NewRS256Signer(privKey, nil),
			WithJSONMarshaller(jsonMarshalWithSpace),
			WithSaltFnc(func() (string, error) {
				return sampleSalt, nil
			}))
		r.NoError(err)
		combinedFormatForIssuance, err := token.Serialize(false)
		require.NoError(t, err)

		cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)
		require.Equal(t, 1, len(cfi.Disclosures))

		var parsedClaims map[string]interface{}
		err = verifyRS256ViaGoJose(cfi.SDJWT, pubKey, &parsedClaims)
		r.NoError(err)

		parsedClaimsBytes, err := json.Marshal(parsedClaims)
		require.NoError(t, err)

		prettyJSON, err := prettyPrint(parsedClaimsBytes)
		require.NoError(t, err)

		fmt.Println(prettyJSON)

		expectedHashWithSpaces := expectedHashWithSpaces
		require.True(t, existsInDisclosures(parsedClaims, expectedHashWithSpaces))

		err = verifyRS256(cfi.SDJWT, pubKey)
		r.NoError(err)
	})

	t.Run("Create Complex Claims JWS signed by EdDSA", func(t *testing.T) {
		r := require.New(t)

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		complexClaims := createComplexClaims()

		issued := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
		expiry := time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC)
		notBefore := time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)

		var newOpts []NewOpt

		newOpts = append(newOpts,
			WithIssuedAt(jwt.NewNumericDate(issued)),
			WithExpiry(jwt.NewNumericDate(expiry)),
			WithNotBefore(jwt.NewNumericDate(notBefore)),
			WithJTI("jti"),
			WithID("id"),
			WithSubject("subject"),
			WithAudience("audience"),
			WithSaltFnc(func() (string, error) {
				return generateSalt(128 / 8)
			}),
			WithJSONMarshaller(json.Marshal),
			WithHashAlgorithm(crypto.SHA256),
		)

		token, err := New(issuer, complexClaims, nil, afjwt.NewEd25519Signer(privKey), newOpts...)
		r.NoError(err)
		combinedFormatForIssuance, err := token.Serialize(false)
		require.NoError(t, err)

		fmt.Printf(combinedFormatForIssuance)

		cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)
		require.Equal(t, 7, len(cfi.Disclosures))

		var parsedClaims map[string]interface{}
		err = verifyEd25519ViaGoJose(cfi.SDJWT, pubKey, &parsedClaims)
		r.NoError(err)

		printObject(t, "Parsed Claims:", parsedClaims)

		r.Equal(issuer, parsedClaims["iss"])
		r.Equal("audience", parsedClaims["aud"])
		r.Equal("subject", parsedClaims["sub"])
		r.Equal("id", parsedClaims["id"])
		r.Equal("jti", parsedClaims["jti"])
		r.Equal("sha-256", parsedClaims["_sd_alg"])

		_, ok := parsedClaims["nbf"]
		r.True(ok)

		_, ok = parsedClaims["iat"]
		r.True(ok)

		_, ok = parsedClaims["exp"]
		r.True(ok)

		err = verifyEd25519(cfi.SDJWT, pubKey)
		r.NoError(err)
	})

	t.Run("Create Complex Claims JWS with structured claims flag", func(t *testing.T) {
		r := require.New(t)

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		complexClaims := createComplexClaims()

		var newOpts []NewOpt

		newOpts = append(newOpts,
			WithStructuredClaims(true),
		)

		token, err := New(issuer, complexClaims, nil, afjwt.NewEd25519Signer(privKey), newOpts...)
		r.NoError(err)
		combinedFormatForIssuance, err := token.Serialize(false)
		require.NoError(t, err)

		fmt.Printf(combinedFormatForIssuance)

		cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)
		// expected 6 simple + 4 address object disclosures
		require.Equal(t, 10, len(cfi.Disclosures))

		var parsedClaims map[string]interface{}
		err = verifyEd25519ViaGoJose(cfi.SDJWT, pubKey, &parsedClaims)
		r.NoError(err)

		parsedClaimsBytes, err := json.Marshal(parsedClaims)
		require.NoError(t, err)

		prettyJSON, err := prettyPrint(parsedClaimsBytes)
		require.NoError(t, err)

		fmt.Println(prettyJSON)

		err = verifyEd25519(cfi.SDJWT, pubKey)
		r.NoError(err)
	})

	t.Run("Create Mixed (SD + non-SD) JWS with structured claims flag", func(t *testing.T) {
		r := require.New(t)

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		complexClaims := map[string]interface{}{
			"degree": map[string]interface{}{
				"degree": "MIT",
				"type":   "BachelorDegree",
				"id":     "some-id",
			},
			"name":   "Jayden Doe",
			"id":     "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
		}

		var newOpts []NewOpt

		newOpts = append(newOpts,
			WithStructuredClaims(true),
			WithNonSelectivelyDisclosableClaims([]string{"id", "degree.type"}),
		)

		token, err := New(issuer, complexClaims, nil, afjwt.NewEd25519Signer(privKey), newOpts...)
		r.NoError(err)

		var tokenClaims map[string]interface{}
		err = token.DecodeClaims(&tokenClaims)
		r.NoError(err)

		printObject(t, "Token Claims", tokenClaims)

		combinedFormatForIssuance, err := token.Serialize(false)
		require.NoError(t, err)

		fmt.Printf(combinedFormatForIssuance)

		cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)
		require.Equal(t, 4, len(cfi.Disclosures))

		id, err := jsonpath.Get("$.id", tokenClaims)
		r.NoError(err)
		r.Equal("did:example:ebfeb1f712ebc6f1c276e12ec21", id)

		degreeType, err := jsonpath.Get("$.degree.type", tokenClaims)
		r.NoError(err)
		r.Equal("BachelorDegree", degreeType)

		degreeID, err := jsonpath.Get("$.degree.id", tokenClaims)
		r.Error(err)
		r.Nil(degreeID)
		r.Contains(err.Error(), "unknown key id")
	})

	t.Run("Create Mixed (SD + non-SD) JWS with flat claims flag, SHA-512", func(t *testing.T) {
		r := require.New(t)

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		complexClaims := map[string]interface{}{
			"degree": map[string]interface{}{
				"degree": "MIT",
				"type":   "BachelorDegree",
				"id":     "some-id",
			},
			"name":   "Jayden Doe",
			"id":     "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
		}

		var newOpts []NewOpt

		newOpts = append(newOpts,
			WithNonSelectivelyDisclosableClaims([]string{"id", "degree.type"}),
			WithHashAlgorithm(crypto.SHA512),
		)

		token, err := New(issuer, complexClaims, nil, afjwt.NewEd25519Signer(privKey), newOpts...)
		r.NoError(err)

		var tokenClaims map[string]interface{}
		err = token.DecodeClaims(&tokenClaims)
		r.NoError(err)

		r.Equal("sha-512", tokenClaims[common.SDAlgorithmKey])

		printObject(t, "Token Claims", tokenClaims)

		combinedFormatForIssuance, err := token.Serialize(false)
		require.NoError(t, err)

		fmt.Printf(combinedFormatForIssuance)

		cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)
		require.Equal(t, 3, len(cfi.Disclosures))

		id, err := jsonpath.Get("$.id", tokenClaims)
		r.NoError(err)
		r.Equal("did:example:ebfeb1f712ebc6f1c276e12ec21", id)

		degreeType, err := jsonpath.Get("$.degree.type", tokenClaims)
		r.Error(err)
		r.Nil(degreeType)
		r.Contains(err.Error(), "unknown key degree")
	})

	t.Run("Create SD-JWS with decoy disclosures", func(t *testing.T) {
		r := require.New(t)

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		verifier, e := afjwt.NewEd25519Verifier(pubKey)
		r.NoError(e)

		token, err := New(issuer, claims, nil, afjwt.NewEd25519Signer(privKey),
			WithDecoyDigests(true))
		r.NoError(err)
		combinedFormatForIssuance, err := token.Serialize(false)
		r.NoError(err)

		cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)
		r.Equal(1, len(cfi.Disclosures))

		afjwtToken, _, err := afjwt.Parse(cfi.SDJWT, afjwt.WithSignatureVerifier(verifier))
		r.NoError(err)

		var parsedClaims map[string]interface{}
		err = afjwtToken.DecodeClaims(&parsedClaims)
		r.NoError(err)

		digests, err := common.GetDisclosureDigests(parsedClaims)
		require.NoError(t, err)

		if len(digests) < 1+decoyMinElements || len(digests) > 1+decoyMaxElements {
			r.Fail(fmt.Sprintf("invalid number of digests: %d", len(digests)))
		}
	})

	t.Run("Create SD-JWS V5 with structured claims, recursive SD and SD array elements", func(t *testing.T) {
		r := require.New(t)

		complexClaims := createComplexClaimsWithSlice()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		verifier, e := afjwt.NewEd25519Verifier(pubKey)
		r.NoError(e)

		token, err := New(issuer, complexClaims, nil, afjwt.NewEd25519Signer(privKey),
			WithSDJWTVersion(common.SDJWTVersionV5),
			WithStructuredClaims(true),
			WithAlwaysIncludeObjects([]string{"address.countryCodes", "address.extra"}),
			WithNonSelectivelyDisclosableClaims([]string{"address.cities[1]", "address.region"}),
			WithRecursiveClaimsObjects([]string{"address.extra.recursive"}),
		)
		r.NoError(err)
		combinedFormatForIssuance, err := token.Serialize(false)
		r.NoError(err)

		cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)
		r.Equal(6, len(cfi.Disclosures))

		afjwtToken, _, err := afjwt.Parse(cfi.SDJWT, afjwt.WithSignatureVerifier(verifier))
		r.NoError(err)

		var parsedClaims map[string]interface{}
		err = afjwtToken.DecodeClaims(&parsedClaims)
		r.NoError(err)

		digests, err := common.GetDisclosureDigests(parsedClaims)
		require.NoError(t, err)
		require.Empty(t, digests)
	})

	t.Run("Create JWS with holder public key", func(t *testing.T) {
		r := require.New(t)

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		_, holderPublicKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		holderJWK, err := jwksupport.JWKFromKey(holderPublicKey)
		require.NoError(t, err)

		token, err := New(issuer, claims, nil, afjwt.NewEd25519Signer(privKey),
			WithHolderPublicKey(holderJWK))
		r.NoError(err)
		combinedFormatForIssuance, err := token.Serialize(false)
		require.NoError(t, err)

		cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)
		require.Equal(t, 1, len(cfi.Disclosures))

		var parsedClaims map[string]interface{}
		err = verifyEd25519ViaGoJose(cfi.SDJWT, pubKey, &parsedClaims)
		r.NoError(err)
		require.NotEmpty(t, parsedClaims["cnf"])

		parsedClaimsBytes, err := json.Marshal(parsedClaims)
		require.NoError(t, err)

		prettyJSON, err := prettyPrint(parsedClaimsBytes)
		require.NoError(t, err)

		fmt.Println(prettyJSON)
	})

	t.Run("error - claims contain _sd key (top level object)", func(t *testing.T) {
		r := require.New(t)

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		complexClaims := map[string]interface{}{
			"_sd": "whatever",
		}

		token, err := New(issuer, complexClaims, nil, afjwt.NewEd25519Signer(privKey))
		r.Error(err)
		r.Nil(token)
		r.Contains(err.Error(), "key '_sd' cannot be present in the claims")
	})

	t.Run("error - claims contain _sd key (inner object)", func(t *testing.T) {
		r := require.New(t)

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		complexClaims := map[string]interface{}{
			"degree": map[string]interface{}{
				"_sd":  "whatever",
				"type": "BachelorDegree",
			},
		}

		token, err := New(issuer, complexClaims, nil, afjwt.NewEd25519Signer(privKey))
		r.Error(err)
		r.Nil(token)
		r.Contains(err.Error(), "key '_sd' cannot be present in the claims")
	})

	t.Run("error - invalid holder public key", func(t *testing.T) {
		r := require.New(t)

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		token, err := New(issuer, claims, nil, afjwt.NewEd25519Signer(privKey),
			WithHolderPublicKey(&jwk.JWK{JSONWebKey: jose.JSONWebKey{Key: "abc"}}))
		r.Error(err)
		r.Nil(token)

		r.Contains(err.Error(),
			"failed to merge payload and digests: json: error calling MarshalJSON for type *jwk.JWK: go-jose/go-jose: unknown key type 'string'") //nolint:lll
	})

	t.Run("error - create decoy disclosures failed", func(t *testing.T) {
		r := require.New(t)

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		token, err := New(issuer, claims, nil, afjwt.NewEd25519Signer(privKey),
			WithDecoyDigests(true),
			WithSaltFnc(func() (string, error) {
				return "", fmt.Errorf("salt error")
			}))
		r.Error(err)
		r.Nil(token)
		r.Contains(err.Error(), "failed to create decoy disclosures: salt error")
	})

	t.Run("error - wrong hash function", func(t *testing.T) {
		r := require.New(t)

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		r.NoError(err)
		token, err := New(issuer, claims, nil, afjwt.NewRS256Signer(privKey, nil),
			WithJSONMarshaller(jsonMarshalWithSpace),
			WithSaltFnc(func() (string, error) {
				return sampleSalt, nil
			}),
			WithHashAlgorithm(0))
		r.Error(err)
		r.Nil(token)
		r.Contains(err.Error(), "hash disclosure: hash function not available for: 0")
	})

	t.Run("error - get salt error", func(t *testing.T) {
		r := require.New(t)

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		r.NoError(err)
		token, err := New(issuer, claims, nil, afjwt.NewRS256Signer(privKey, nil),
			WithJSONMarshaller(jsonMarshalWithSpace),
			WithSaltFnc(func() (string, error) {
				return "", fmt.Errorf("salt error")
			}))
		r.Error(err)
		r.Nil(token)
		r.Contains(err.Error(), "create disclosure: generate salt: salt error")
	})

	t.Run("error - marshal error", func(t *testing.T) {
		r := require.New(t)

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		r.NoError(err)
		token, err := New(issuer, claims, nil, afjwt.NewRS256Signer(privKey, nil),
			WithJSONMarshaller(func(v interface{}) ([]byte, error) {
				return nil, fmt.Errorf("marshal error")
			}))
		r.Error(err)
		r.Nil(token)
		r.Contains(err.Error(), "create disclosure: marshal disclosure: marshal error")
	})
}

func TestNewFromVC(t *testing.T) {
	r := require.New(t)

	_, issuerPrivateKey, e := ed25519.GenerateKey(rand.Reader)
	r.NoError(e)

	signer := afjwt.NewEd25519Signer(issuerPrivateKey)

	t.Run("success - structured claims + holder binding", func(t *testing.T) {
		holderPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		holderPublicJWK, err := jwksupport.JWKFromKey(holderPublicKey)
		require.NoError(t, err)

		// create VC - we will use template here
		var vc map[string]interface{}
		err = json.Unmarshal([]byte(sampleVCFull), &vc)
		r.NoError(err)

		token, err := NewFromVC(vc, nil, signer,
			WithHolderPublicKey(holderPublicJWK),
			WithStructuredClaims(true),
			WithNonSelectivelyDisclosableClaims([]string{"id", "degree.type"}))
		r.NoError(err)

		vcCombinedFormatForIssuance, err := token.Serialize(false)
		r.NoError(err)

		fmt.Println(fmt.Sprintf("issuer SD-JWT: %s", vcCombinedFormatForIssuance))

		var vcWithSelectedDisclosures map[string]interface{}
		err = token.DecodeClaims(&vcWithSelectedDisclosures)
		r.NoError(err)

		printObject(t, "VC with selected disclosures", vcWithSelectedDisclosures)

		id, err := jsonpath.Get("$.vc.credentialSubject.id", vcWithSelectedDisclosures)
		r.NoError(err)
		r.Equal("did:example:ebfeb1f712ebc6f1c276e12ec21", id)

		degreeType, err := jsonpath.Get("$.vc.credentialSubject.degree.type", vcWithSelectedDisclosures)
		r.NoError(err)
		r.Equal("BachelorDegree", degreeType)

		degreeID, err := jsonpath.Get("$.vc.credentialSubject.degree.id", vcWithSelectedDisclosures)
		r.Error(err)
		r.Nil(degreeID)
		r.Contains(err.Error(), "unknown key id")
	})

	t.Run("success - structured claims + holder binding + SD JWT V5 format", func(t *testing.T) {
		holderPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		holderPublicJWK, err := jwksupport.JWKFromKey(holderPublicKey)
		require.NoError(t, err)

		// create VC - we will use template here
		var vc map[string]interface{}
		err = json.Unmarshal([]byte(sampleSDJWTV5Full), &vc)
		r.NoError(err)

		token, err := NewFromVC(vc, nil, signer,
			WithHolderPublicKey(holderPublicJWK),
			WithStructuredClaims(true),
			WithNonSelectivelyDisclosableClaims([]string{"id", "degree.type"}),
			WithSDJWTVersion(common.SDJWTVersionV5))
		r.NoError(err)

		vcCombinedFormatForIssuance, err := token.Serialize(false)
		r.NoError(err)

		fmt.Println(fmt.Sprintf("issuer SD-JWT: %s", vcCombinedFormatForIssuance))

		var vcWithSelectedDisclosures map[string]interface{}
		err = token.DecodeClaims(&vcWithSelectedDisclosures)
		r.NoError(err)

		printObject(t, "VC with selected disclosures", vcWithSelectedDisclosures)

		id, err := jsonpath.Get("$.credentialSubject.id", vcWithSelectedDisclosures)
		r.NoError(err)
		r.Equal("did:example:ebfeb1f712ebc6f1c276e12ec21", id)

		degreeType, err := jsonpath.Get("$.credentialSubject.degree.type", vcWithSelectedDisclosures)
		r.NoError(err)
		r.Equal("BachelorDegree", degreeType)

		degreeID, err := jsonpath.Get("$.credentialSubject.degree.id", vcWithSelectedDisclosures)
		r.Error(err)
		r.Nil(degreeID)
		r.Contains(err.Error(), "unknown key id")
	})

	t.Run("success - flat claims + holder binding", func(t *testing.T) {
		holderPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		holderPublicJWK, err := jwksupport.JWKFromKey(holderPublicKey)
		require.NoError(t, err)

		// create VC - we will use template here
		var vc map[string]interface{}
		err = json.Unmarshal([]byte(sampleVCFull), &vc)
		r.NoError(err)

		token, err := NewFromVC(vc, nil, signer,
			WithHolderPublicKey(holderPublicJWK),
			WithNonSelectivelyDisclosableClaims([]string{"id"}))
		r.NoError(err)

		vcCombinedFormatForIssuance, err := token.Serialize(false)
		r.NoError(err)

		fmt.Println(fmt.Sprintf("issuer SD-JWT: %s", vcCombinedFormatForIssuance))

		var vcWithSelectedDisclosures map[string]interface{}
		err = token.DecodeClaims(&vcWithSelectedDisclosures)
		r.NoError(err)

		printObject(t, "VC with selected disclosures", vcWithSelectedDisclosures)

		id, err := jsonpath.Get("$.vc.credentialSubject.id", vcWithSelectedDisclosures)
		r.NoError(err)
		r.Equal("did:example:ebfeb1f712ebc6f1c276e12ec21", id)
	})

	t.Run("error - missing credential subject", func(t *testing.T) {
		vc := make(map[string]interface{})

		token, err := NewFromVC(vc, nil, signer,
			WithID("did:example:ebfeb1f712ebc6f1c276e12ec21"),
			WithStructuredClaims(true))
		r.Error(err)
		r.Nil(token)

		r.Contains(err.Error(), "credential subject not found")
	})

	t.Run("error - credential subject no an object", func(t *testing.T) {
		vc := map[string]interface{}{
			"vc": map[string]interface{}{
				"credentialSubject": "invalid",
			},
		}

		token, err := NewFromVC(vc, nil, signer,
			WithID("did:example:ebfeb1f712ebc6f1c276e12ec21"),
			WithStructuredClaims(true))
		r.Error(err)
		r.Nil(token)

		r.Contains(err.Error(), "credential subject must be an object")
	})

	t.Run("error - signing error", func(t *testing.T) {
		// create VC - we will use template here
		var vc map[string]interface{}
		err := json.Unmarshal([]byte(sampleVCFull), &vc)
		r.NoError(err)

		token, err := NewFromVC(vc, nil, &mockSigner{Err: fmt.Errorf("signing error")},
			WithID("did:example:ebfeb1f712ebc6f1c276e12ec21"))
		r.Error(err)
		r.Nil(token)

		r.Contains(err.Error(), "create JWS: sign JWS: sign JWS verification data: signing error")
	})
}

func TestJSONWebToken_DecodeClaims(t *testing.T) {
	token, err := getValidJSONWebToken(
		WithJSONMarshaller(jsonMarshalWithSpace),
		WithSaltFnc(func() (string, error) {
			return sampleSalt, nil
		}))
	require.NoError(t, err)

	var tokensMap map[string]interface{}

	err = token.DecodeClaims(&tokensMap)
	require.NoError(t, err)

	expectedHashWithSpaces := expectedHashWithSpaces
	require.True(t, existsInDisclosures(tokensMap, expectedHashWithSpaces))

	var claims Claims

	err = token.DecodeClaims(&claims)
	require.NoError(t, err)
	require.Equal(t, claims.Issuer, issuer)

	token, err = getJSONWebTokenWithInvalidPayload()
	require.NoError(t, err)

	err = token.DecodeClaims(&claims)
	require.Error(t, err)
}

func TestJSONWebToken_LookupStringHeader(t *testing.T) {
	token, err := getValidJSONWebToken()
	require.NoError(t, err)

	require.Equal(t, "JWT", token.LookupStringHeader("typ"))

	require.Empty(t, token.LookupStringHeader("undef"))

	token.SignedJWT.Headers["not_str"] = 55
	require.Empty(t, token.LookupStringHeader("not_str"))
}

func TestJSONWebToken_Serialize(t *testing.T) {
	token, err := getValidJSONWebToken()
	require.NoError(t, err)

	tokenSerialized, err := token.Serialize(false)
	require.NoError(t, err)
	require.NotEmpty(t, tokenSerialized)

	// cannot serialize without signature
	token.SignedJWT = nil
	tokenSerialized, err = token.Serialize(false)
	require.Error(t, err)
	require.EqualError(t, err, "JWS serialization is supported only")
	require.Empty(t, tokenSerialized)
}

func TestJSONWebToken_hashDisclosure(t *testing.T) {
	t.Run("success - data from spec", func(t *testing.T) {
		dh, err := common.GetHash(defaultHash, "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0")
		require.NoError(t, err)
		require.Equal(t, "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY", dh)
	})
}

func TestJSONWebToken_createDisclosure(t *testing.T) {
	t.Run("success - given name", func(t *testing.T) {
		nOpts := getOpts(
			WithJSONMarshaller(jsonMarshalWithSpace),
			WithSaltFnc(func() (string, error) {
				return sampleSalt, nil
			}))

		// Disclosure data from spec: ["3jqcb67z9wks08zwiK7EyQ", "given_name", "John"]
		expectedDisclosureWithSpaces := "WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
		expectedHashWithSpaces := expectedHashWithSpaces

		disclosure, err := NewSDJWTBuilderV2().createDisclosure("given_name", "John", nOpts)
		require.NoError(t, err)
		require.Equal(t, expectedDisclosureWithSpaces, disclosure.Result)

		dh, err := common.GetHash(defaultHash, disclosure.Result)
		require.NoError(t, err)
		require.Equal(t, expectedHashWithSpaces, dh)
	})

	t.Run("success - family name", func(t *testing.T) {
		// Disclosure data from spec: ["_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius"]

		expectedDisclosureWithoutSpaces := "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd"
		expectedDisclosureWithSpaces := "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"

		nOpts := getOpts(
			WithSaltFnc(func() (string, error) {
				return "_26bc4LT-ac6q2KI6cBW5es", nil
			}))

		disclosure, err := NewSDJWTBuilderV2().createDisclosure("family_name", "Möbius", nOpts)
		require.NoError(t, err)
		require.Equal(t, expectedDisclosureWithoutSpaces, disclosure.Result)

		nOpts = getOpts(
			WithJSONMarshaller(jsonMarshalWithSpace),
			WithSaltFnc(func() (string, error) {
				return "_26bc4LT-ac6q2KI6cBW5es", nil
			}))

		disclosure, err = NewSDJWTBuilderV2().createDisclosure("family_name", "Möbius", nOpts)
		require.NoError(t, err)
		require.Equal(t, expectedDisclosureWithSpaces, disclosure.Result)
	})
}

func getOpts(opts ...NewOpt) *newOpts {
	nOpts := &newOpts{
		jsonMarshal: json.Marshal,
		HashAlg:     defaultHash,
	}

	for _, opt := range opts {
		opt(nOpts)
	}

	return nOpts
}

func getValidJSONWebToken(opts ...NewOpt) (*SelectiveDisclosureJWT, error) {
	headers := map[string]interface{}{"typ": "JWT", "alg": "EdDSA"}
	claims := map[string]interface{}{"given_name": "John"}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	signer := afjwt.NewEd25519Signer(privKey)

	return New(issuer, claims, headers, signer, opts...)
}

func getJSONWebTokenWithInvalidPayload() (*SelectiveDisclosureJWT, error) {
	token, err := getValidJSONWebToken()
	if err != nil {
		return nil, err
	}

	// hack the token
	token.SignedJWT.Payload = getUnmarshallableMap()

	return token, nil
}

func verifyEd25519ViaGoJose(jws string, pubKey ed25519.PublicKey, claims interface{}) error {
	jwtToken, err := jwt.ParseSigned(jws)
	if err != nil {
		return fmt.Errorf("parse VC from signed JWS: %w", err)
	}

	if err = jwtToken.Claims(pubKey, claims); err != nil {
		return fmt.Errorf("verify JWT signature: %w", err)
	}

	return nil
}

func verifyRS256ViaGoJose(jws string, pubKey *rsa.PublicKey, claims interface{}) error {
	jwtToken, err := jwt.ParseSigned(jws)
	if err != nil {
		return fmt.Errorf("parse VC from signed JWS: %w", err)
	}

	if err = jwtToken.Claims(pubKey, claims); err != nil {
		return fmt.Errorf("verify JWT signature: %w", err)
	}

	return nil
}

func getUnmarshallableMap() map[string]interface{} {
	return map[string]interface{}{"error": map[chan int]interface{}{make(chan int): 6}}
}

func createClaims() map[string]interface{} {
	claims := map[string]interface{}{
		"given_name": "John",
	}

	return claims
}

func createComplexClaims() map[string]interface{} {
	claims := map[string]interface{}{
		"sub":          "john_doe_42",
		"given_name":   "John",
		"family_name":  "Doe",
		"email":        "johndoe@example.com",
		"phone_number": "+1-202-555-0101",
		"birthdate":    "1940-01-01",
		"address": map[string]interface{}{
			"street_address": "123 Main St",
			"locality":       "Anytown",
			"region":         "Anystate",
			"country":        "US",
		},
	}

	return claims
}

func createComplexClaimsWithSlice() map[string]interface{} {
	claims := map[string]interface{}{
		"address": map[string]interface{}{
			"locality":     "Schulpforta",
			"region":       "Sachsen-Anhalt",
			"countryCodes": []string{"UA", "PL"},
			"cities":       []string{"Albuquerque", "El Paso"},
			"extra": map[string]interface{}{
				"recursive": map[string]interface{}{
					"key1": "value1",
				},
			},
		},
	}

	return claims
}

func verifyEd25519(jws string, pubKey ed25519.PublicKey) error {
	v, err := afjwt.NewEd25519Verifier(pubKey)
	if err != nil {
		return err
	}

	sVerifier := afjose.NewCompositeAlgSigVerifier(afjose.AlgSignatureVerifier{
		Alg:      "EdDSA",
		Verifier: v,
	})

	token, _, err := afjwt.Parse(jws, afjwt.WithSignatureVerifier(sVerifier))
	if err != nil {
		return err
	}

	if token == nil {
		return errors.New("nil token")
	}

	return nil
}

func verifyRS256(jws string, pubKey *rsa.PublicKey) error {
	v := afjwt.NewRS256Verifier(pubKey)

	sVerifier := afjose.NewCompositeAlgSigVerifier(afjose.AlgSignatureVerifier{
		Alg:      "RS256",
		Verifier: v,
	})

	token, _, err := afjwt.Parse(jws, afjwt.WithSignatureVerifier(sVerifier))
	if err != nil {
		return err
	}

	if token == nil {
		return errors.New("nil token")
	}

	return nil
}

func existsInDisclosures(claims map[string]interface{}, val string) bool {
	disclosuresObj, ok := claims[common.SDKey]
	if !ok {
		return false
	}

	disclosures, ok := disclosuresObj.([]interface{})
	if !ok {
		return false
	}

	for _, d := range disclosures {
		if d.(string) == val {
			return true
		}
	}

	return false
}

func jsonMarshalWithSpace(v interface{}) ([]byte, error) {
	vBytes, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	return []byte(strings.ReplaceAll(string(vBytes), ",", ", ")), nil
}

func prettyPrint(msg []byte) (string, error) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, msg, "", "\t")
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}

func printObject(t *testing.T, name string, obj interface{}) {
	t.Helper()

	objBytes, err := json.Marshal(obj)
	require.NoError(t, err)

	prettyJSON, err := prettyPrint(objBytes)
	require.NoError(t, err)

	fmt.Println(name + ":")
	fmt.Println(prettyJSON)
}

// Signer defines JWS Signer interface. It makes signing of data and provides custom JWS headers relevant to the signer.
type mockSigner struct {
	Err error
}

// Sign signs.
func (m *mockSigner) Sign(_ []byte) ([]byte, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return nil, nil
}

// Headers provides JWS headers.
func (m *mockSigner) Headers() afjose.Headers {
	headers := make(afjose.Headers)
	headers["alg"] = "EdDSA"

	return headers
}

const sampleVCFull = `
{
	"iat": 1673987547,
	"iss": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	"jti": "http://example.edu/credentials/1872",
	"nbf": 1673987547,
	"sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
	"vc": {
		"@context": [
			"https://www.w3.org/2018/credentials/v1"
		],
		"credentialSubject": {
			"degree": {
				"degree": "MIT",
				"type": "BachelorDegree",
				"id": "some-id"
			},
			"name": "Jayden Doe",
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
		},
		"first_name": "First name",
		"id": "http://example.edu/credentials/1872",
		"info": "Info",
		"issuanceDate": "2023-01-17T22:32:27.468109817+02:00",
		"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
		"last_name": "Last name",
		"type": "VerifiableCredential"
	}
}`

const sampleSDJWTV5Full = `
{
	"iat": 1673987547,
	"iss": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	"jti": "http://example.edu/credentials/1872",
	"nbf": 1673987547,
	"sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
	"@context": [
		"https://www.w3.org/2018/credentials/v1"
	],
	"credentialSubject": {
		"degree": {
			"degree": "MIT",
			"type": "BachelorDegree",
			"id": "some-id"
		},
		"name": "Jayden Doe",
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
	},
	"first_name": "First name",
	"id": "http://example.edu/credentials/1872",
	"info": "Info",
	"issuanceDate": "2023-01-17T22:32:27.468109817+02:00",
	"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	"last_name": "Last name",
	"type": "VerifiableCredential"
}`
