/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/square/go-jose/v3/json"
	"github.com/square/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
)

type CustomClaim struct {
	*Claims

	PrivateClaim1 string `json:"privateClaim1,omitempty"`
}

func TestNew(t *testing.T) {
	issued := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	expiry := time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC)
	notBefore := time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)

	claims := &CustomClaim{
		Claims: &Claims{
			Issuer:    "iss",
			Subject:   "sub",
			Audience:  []string{"aud"},
			Expiry:    jwt.NewNumericDate(expiry),
			NotBefore: jwt.NewNumericDate(notBefore),
			IssuedAt:  jwt.NewNumericDate(issued),
			ID:        "id",
		},

		PrivateClaim1: "private claim",
	}

	t.Run("Create JWS signed by EdDSA", func(t *testing.T) {
		r := require.New(t)

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		token, err := New(claims)
		r.NoError(err)
		jws, err := token.SerializeSigned(newEd25519Signer(privKey), false)
		require.NoError(t, err)

		var parsedClaims CustomClaim
		err = verifyEd25519ViaGoJose(jws, pubKey, &parsedClaims)
		r.NoError(err)
		r.Equal(*claims, parsedClaims)

		err = verifyEd25519(jws, pubKey)
		r.NoError(err)
	})

	t.Run("Create JWS signed by RS256", func(t *testing.T) {
		r := require.New(t)

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		r.NoError(err)

		pubKey := &privKey.PublicKey

		token, err := New(claims)
		r.NoError(err)
		jws, err := token.SerializeSigned(newRS256Signer(privKey, nil), false)
		require.NoError(t, err)

		var parsedClaims CustomClaim
		err = verifyRS256ViaGoJose(jws, pubKey, &parsedClaims)
		r.NoError(err)
		r.Equal(*claims, parsedClaims)

		err = verifyRS256(jws, pubKey)
		r.NoError(err)
	})

	t.Run("Create unsecured JWT", func(t *testing.T) {
		r := require.New(t)

		token, err := New(claims)
		r.NoError(err)
		jwtUnsecured, err := token.SerializeUnsecured(map[string]interface{}{"custom": "ok"}, false)
		r.NoError(err)
		r.NotEmpty(jwtUnsecured)

		parsedJWT, err := Parse(jwtUnsecured, WithSignatureVerifier(UnsecuredJWTVerifier()))
		r.NoError(err)
		r.NotNil(parsedJWT)

		var parsedClaims CustomClaim
		err = parsedJWT.DecodeClaims(&parsedClaims)
		r.NoError(err)
		r.Equal(*claims, parsedClaims)
	})

	t.Run("Invalid claims", func(t *testing.T) {
		token, err := New("not JSON claims")
		require.Error(t, err)
		require.Nil(t, token)
	})
}

func TestWithJWTDetachedPayload(t *testing.T) {
	detachedPayloadOpt := WithJWTDetachedPayload([]byte("payload"))
	require.NotNil(t, detachedPayloadOpt)

	opts := &parseOpts{}
	detachedPayloadOpt(opts)
	require.Equal(t, []byte("payload"), opts.detachedPayload)
}

func TestParse(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	signer := newEd25519Signer(privKey)
	claims := map[string]interface{}{"iss": "Albert"}

	token, err := New(claims)
	r.NoError(err)
	jws, err := token.SerializeSigned(signer, false)
	r.NoError(err)

	verifier, err := newEd25519Verifier(pubKey)
	r.NoError(err)

	jsonWebToken, err := Parse(jws, WithSignatureVerifier(verifier))
	r.NoError(err)

	var parsedClaims map[string]interface{}
	err = jsonWebToken.DecodeClaims(&parsedClaims)
	r.NoError(err)

	r.Equal(claims, parsedClaims)

	// parse detached JWT
	jwsParts := strings.Split(jws, ".")
	jwsDetached := fmt.Sprintf("%s..%s", jwsParts[0], jwsParts[2])

	jwsPayload, err := base64.RawURLEncoding.DecodeString(jwsParts[1])
	require.NoError(t, err)

	jsonWebToken, err = Parse(jwsDetached,
		WithSignatureVerifier(verifier), WithJWTDetachedPayload(jwsPayload))
	r.NoError(err)
	r.NotNil(r, jsonWebToken)

	// claims is not JSON
	jws, err = buildJWS(signer, "not JSON")
	r.NoError(err)
	token, err = Parse(jws, WithSignatureVerifier(verifier))
	r.Error(err)
	r.Contains(err.Error(), "read JWT claims from JWS payload")
	r.Nil(token)

	// type is not JWT
	signer.headers = map[string]interface{}{"alg": "EdDSA", "typ": "JWM"}
	jws, err = buildJWS(signer, map[string]interface{}{"iss": "Albert"})
	r.NoError(err)
	token, err = Parse(jws, WithSignatureVerifier(verifier))
	r.Error(err)
	r.Contains(err.Error(), "typ is not JWT")
	r.Nil(token)

	// content type is not empty (equals to JWT)
	signer.headers = map[string]interface{}{"alg": "EdDSA", "typ": "JWT", "cty": "JWT"}
	jws, err = buildJWS(signer, map[string]interface{}{"iss": "Albert"})
	r.NoError(err)
	token, err = Parse(jws, WithSignatureVerifier(verifier))
	r.Error(err)
	r.Contains(err.Error(), "nested JWT is not supported")
	r.Nil(token)

	// handle compact JWS of invalid form
	token, err = Parse("invalid.compact.JWS")
	r.Error(err)
	r.Contains(err.Error(), "parse JWT from compact JWS")
	r.Nil(token)

	// pass not compact JWS
	token, err = Parse("invalid jws")
	r.Error(err)
	r.EqualError(err, "JWT of compacted JWS form is supported only")
	r.Nil(token)
}

func buildJWS(signer jose.Signer, claims interface{}) (string, error) {
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	jws, err := jose.NewJWS(nil, nil, claimsBytes, signer)
	if err != nil {
		return "", err
	}

	return jws.SerializeCompact(false)
}

func TestJSONWebToken_DecodeClaims(t *testing.T) {
	token := getValidJSONWebToken()

	var tokensMap map[string]interface{}

	err := token.DecodeClaims(&tokensMap)
	require.NoError(t, err)
	require.Equal(t, map[string]interface{}{"iss": "Albert"}, tokensMap)

	var claims Claims

	err = token.DecodeClaims(&claims)
	require.NoError(t, err)
	require.Equal(t, Claims{Issuer: "Albert"}, claims)

	err = getJSONWebTokenWithInvalidPayload().DecodeClaims(&claims)
	require.Error(t, err)
}

func TestJSONWebToken_LookupStringHeader(t *testing.T) {
	token := getValidJSONWebToken()

	require.Equal(t, "JWT", token.LookupStringHeader("typ"))

	require.Empty(t, token.LookupStringHeader("undef"))

	token.Headers["not_str"] = 55
	require.Empty(t, token.LookupStringHeader("not_str"))
}

func TestJSONWebToken_SerializeSigned(t *testing.T) {
	token := getValidJSONWebToken()

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := newEd25519Signer(privKey)

	jws, err := token.SerializeSigned(signer, false)
	require.NoError(t, err)
	require.NotEmpty(t, jws)

	// unmarshallable claims case
	token = getJSONWebTokenWithInvalidPayload()
	jws, err = token.SerializeSigned(signer, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "marshal JWT claims")
	require.Empty(t, jws)
}

func TestJSONWebToken_SerializeUnsecured(t *testing.T) {
	token := getValidJSONWebToken()

	jws, err := token.SerializeUnsecured(nil, false)
	require.NoError(t, err)
	require.NotEmpty(t, jws)

	// unmarshallable claims case
	token = getJSONWebTokenWithInvalidPayload()
	jws, err = token.SerializeUnsecured(nil, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "marshal JWT claims")
	require.Empty(t, jws)
}

func TestUnsecuredJWTVerifier(t *testing.T) {
	verifier := UnsecuredJWTVerifier()

	err := verifier.Verify(map[string]interface{}{"alg": "none"}, nil, nil, nil)
	require.NoError(t, err)

	err = verifier.Verify(map[string]interface{}{}, nil, nil, nil)
	require.Error(t, err)
	require.EqualError(t, err, "alg is not defined")

	err = verifier.Verify(map[string]interface{}{"alg": "EdDSA"}, nil, nil, nil)
	require.Error(t, err)
	require.EqualError(t, err, "alg value is not 'none'")

	err = verifier.Verify(map[string]interface{}{"alg": "none"}, nil, nil, []byte("unexpected signature"))
	require.Error(t, err)
	require.EqualError(t, err, "not empty signature")
}

type testToMapStruct struct {
	TestField string `json:"a"`
}

func Test_toMap(t *testing.T) {
	inputMap := map[string]interface{}{"a": "b"}

	r := require.New(t)

	// pass map
	resultMap, err := toMap(inputMap)
	r.NoError(err)
	r.Equal(inputMap, resultMap)

	// pass []byte
	inputMapBytes, err := json.Marshal(inputMap)
	r.NoError(err)
	resultMap, err = toMap(inputMapBytes)
	r.NoError(err)
	r.Equal(inputMap, resultMap)

	// pass string
	inputMapStr := string(inputMapBytes)
	resultMap, err = toMap(inputMapStr)
	r.NoError(err)
	r.Equal(inputMap, resultMap)

	// pass struct
	s := testToMapStruct{TestField: "b"}
	resultMap, err = toMap(s)
	r.NoError(err)
	r.Equal(inputMap, resultMap)

	// pass invalid []byte
	resultMap, err = toMap([]byte("not JSON"))
	r.Error(err)
	r.Contains(err.Error(), "convert to map")
	r.Nil(resultMap)

	// pass invalid structure
	resultMap, err = toMap(make(chan int))
	r.Error(err)
	r.Contains(err.Error(), "convert to bytes")
	r.Nil(resultMap)
}

func getValidJSONWebToken() *JSONWebToken {
	return &JSONWebToken{
		Headers:   map[string]interface{}{"typ": "JWT", "alg": "EdDSA"},
		Payload:   map[string]interface{}{"iss": "Albert"},
		signature: []byte("signature"),
	}
}

func getJSONWebTokenWithInvalidPayload() *JSONWebToken {
	return &JSONWebToken{
		Headers:   map[string]interface{}{"typ": "JWT", "alg": "EdDSA"},
		Payload:   getUnmarshallableMap(),
		signature: []byte("signature")}
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
