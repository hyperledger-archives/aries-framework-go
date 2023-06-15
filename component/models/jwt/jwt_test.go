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

	"github.com/go-jose/go-jose/v3/json"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
)

type CustomClaim struct {
	*Claims

	PrivateClaim1 string `json:"privateClaim1,omitempty"`
}

func TestNewSigned(t *testing.T) {
	claims := createClaims()

	t.Run("Create JWS signed by EdDSA", func(t *testing.T) {
		r := require.New(t)

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		token, err := NewSigned(claims, nil, NewEd25519Signer(privKey))
		r.NoError(err)
		jws, err := token.Serialize(false)
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

		token, err := NewSigned(claims, nil, NewRS256Signer(privKey, nil))
		r.NoError(err)
		jws, err := token.Serialize(false)
		require.NoError(t, err)

		var parsedClaims CustomClaim
		err = verifyRS256ViaGoJose(jws, pubKey, &parsedClaims)
		r.NoError(err)
		r.Equal(*claims, parsedClaims)

		err = verifyRS256(jws, pubKey)
		r.NoError(err)
	})
}

func TestNewUnsecured(t *testing.T) {
	claims := createClaims()

	t.Run("Create unsecured JWT", func(t *testing.T) {
		r := require.New(t)

		token, err := NewUnsecured(claims, map[string]interface{}{"custom": "ok"})
		r.NoError(err)
		jwtUnsecured, err := token.Serialize(false)
		r.NoError(err)
		r.NotEmpty(jwtUnsecured)

		parsedJWT, _, err := Parse(jwtUnsecured, WithSignatureVerifier(UnsecuredJWTVerifier()))
		r.NoError(err)
		r.NotNil(parsedJWT)

		var parsedClaims CustomClaim
		err = parsedJWT.DecodeClaims(&parsedClaims)
		r.NoError(err)
		r.Equal(*claims, parsedClaims)
	})

	t.Run("Invalid claims", func(t *testing.T) {
		token, err := NewUnsecured("not JSON claims", nil)
		require.Error(t, err)
		require.Nil(t, token)
		require.Contains(t, err.Error(), "unmarshallable claims")

		token, err = NewUnsecured(getUnmarshallableMap(), nil)
		require.Error(t, err)
		require.Nil(t, token)
		require.Contains(t, err.Error(), "marshal JWT claims")

		token, err = NewUnsecured(claims, getUnmarshallableMap())
		require.Error(t, err)
		require.Nil(t, token)
		require.Contains(t, err.Error(), "create JWS")
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

	signer := NewEd25519Signer(privKey)
	claims := map[string]interface{}{"iss": "Albert"}

	token, err := NewSigned(claims, nil, signer)
	r.NoError(err)
	jws, err := token.Serialize(false)
	r.NoError(err)

	verifier, err := NewEd25519Verifier(pubKey)
	r.NoError(err)

	jsonWebToken, _, err := Parse(jws, WithSignatureVerifier(verifier))
	r.NoError(err)

	var parsedClaims map[string]interface{}
	err = jsonWebToken.DecodeClaims(&parsedClaims)
	r.NoError(err)

	r.Equal(claims, parsedClaims)

	// parse without .Payload data
	jsonWebToken, _, err = Parse(jws, WithSignatureVerifier(verifier), WithIgnoreClaimsMapDecoding(true))
	r.NoError(err)
	assert.Nil(t, jsonWebToken.Payload)

	// parse detached JWT
	jwsParts := strings.Split(jws, ".")
	jwsDetached := fmt.Sprintf("%s..%s", jwsParts[0], jwsParts[2])

	jwsPayload, err := base64.RawURLEncoding.DecodeString(jwsParts[1])
	require.NoError(t, err)

	jsonWebToken, _, err = Parse(jwsDetached,
		WithSignatureVerifier(verifier), WithJWTDetachedPayload(jwsPayload))
	r.NoError(err)
	r.NotNil(r, jsonWebToken)

	// claims is not JSON
	jws, err = buildJWS(signer, "not JSON")
	r.NoError(err)
	token, _, err = Parse(jws, WithSignatureVerifier(verifier))
	r.Error(err)
	r.Contains(err.Error(), "read JWT claims from JWS payload")
	r.Nil(token)

	// type is not JWT
	signer.headers = map[string]interface{}{"alg": "EdDSA", "typ": "JWM"}
	jws, err = buildJWS(signer, map[string]interface{}{"iss": "Albert"})
	r.NoError(err)
	token, _, err = Parse(jws, WithSignatureVerifier(verifier))
	r.Error(err)
	r.Contains(err.Error(), "typ is not JWT")
	r.Nil(token)

	// content type is not empty (equals to JWT)
	signer.headers = map[string]interface{}{"alg": "EdDSA", "typ": "JWT", "cty": "JWT"}
	jws, err = buildJWS(signer, map[string]interface{}{"iss": "Albert"})
	r.NoError(err)
	token, _, err = Parse(jws, WithSignatureVerifier(verifier))
	r.Error(err)
	r.Contains(err.Error(), "nested JWT is not supported")
	r.Nil(token)

	// handle compact JWS of invalid form
	token, _, err = Parse("invalid.compact.JWS")
	r.Error(err)
	r.Contains(err.Error(), "parse JWT from compact JWS")
	r.Nil(token)

	// pass not compact JWS
	token, _, err = Parse("invalid jws")
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
	token, err := getValidJSONWebToken()
	require.NoError(t, err)

	var tokensMap map[string]interface{}

	err = token.DecodeClaims(&tokensMap)
	require.NoError(t, err)
	require.Equal(t, map[string]interface{}{"iss": "Albert"}, tokensMap)

	var claims Claims

	err = token.DecodeClaims(&claims)
	require.NoError(t, err)
	require.Equal(t, Claims{Issuer: "Albert"}, claims)

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

	token.Headers["not_str"] = 55
	require.Empty(t, token.LookupStringHeader("not_str"))
}

func TestJSONWebToken_Serialize(t *testing.T) {
	token, err := getValidJSONWebToken()
	require.NoError(t, err)

	tokenSerialized, err := token.Serialize(false)
	require.NoError(t, err)
	require.NotEmpty(t, tokenSerialized)

	// cannot serialize without signature
	token.jws = nil
	tokenSerialized, err = token.Serialize(false)
	require.Error(t, err)
	require.EqualError(t, err, "JWS serialization is supported only")
	require.Empty(t, tokenSerialized)
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

func Test_IsJWS(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	j, err := json.Marshal(map[string]string{"alg": "none"})
	require.NoError(t, err)

	jb64 := base64.RawURLEncoding.EncodeToString(j)

	type args struct {
		data string
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "two parts only",
			args: args{"two parts.only"},
			want: false,
		},
		{
			name: "empty third part",
			args: args{"empty third.part."},
			want: false,
		},
		{
			name: "part 1 is not base64 decoded",
			args: args{"not base64.part2.part3"},
			want: false,
		},
		{
			name: "part 1 is not JSON",
			args: args{fmt.Sprintf("%s.part2.part3", b64)},
			want: false,
		},
		{
			name: "part 2 is not base64 decoded",
			args: args{fmt.Sprintf("%s.not base64.part3", jb64)},
			want: false,
		},
		{
			name: "part 2 is not JSON",
			args: args{fmt.Sprintf("%s.%s.part3", jb64, b64)},
			want: false,
		},
		{
			name: "is JWS",
			args: args{fmt.Sprintf("%s.%s.signature", jb64, jb64)},
			want: true,
		},
	}

	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			if got := IsJWS(tt.args.data); got != tt.want {
				t.Errorf("isJWS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_IsJWTUnsecured(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	j, err := json.Marshal(map[string]string{"alg": "none"})
	require.NoError(t, err)

	jb64 := base64.RawURLEncoding.EncodeToString(j)

	type args struct {
		data string
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "two parts only",
			args: args{"two parts.only"},
			want: false,
		},
		{
			name: "not empty third part",
			args: args{"third.part.not-empty"},
			want: false,
		},
		{
			name: "part 1 is not base64 decoded",
			args: args{"not base64.part2.part3"},
			want: false,
		},
		{
			name: "part 1 is not JSON",
			args: args{fmt.Sprintf("%s.part2.part3", b64)},
			want: false,
		},
		{
			name: "part 2 is not base64 decoded",
			args: args{fmt.Sprintf("%s.not base64.part3", jb64)},
			want: false,
		},
		{
			name: "part 2 is not JSON",
			args: args{fmt.Sprintf("%s.%s.part3", jb64, b64)},
			want: false,
		},
		{
			name: "is JWT unsecured",
			args: args{fmt.Sprintf("%s.%s.", jb64, jb64)},
			want: true,
		},
	}

	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			if got := IsJWTUnsecured(tt.args.data); got != tt.want {
				t.Errorf("isJWTUnsecured() = %v, want %v", got, tt.want)
			}
		})
	}
}

type testToMapStruct struct {
	TestField string `json:"a"`
}

func Test_toMap(t *testing.T) {
	inputMap := map[string]interface{}{"a": "b"}

	r := require.New(t)

	// pass map
	resultMap, err := PayloadToMap(inputMap)
	r.NoError(err)
	r.Equal(inputMap, resultMap)

	// pass []byte
	inputMapBytes, err := json.Marshal(inputMap)
	r.NoError(err)
	resultMap, err = PayloadToMap(inputMapBytes)
	r.NoError(err)
	r.Equal(inputMap, resultMap)

	// pass string
	inputMapStr := string(inputMapBytes)
	resultMap, err = PayloadToMap(inputMapStr)
	r.NoError(err)
	r.Equal(inputMap, resultMap)

	// pass struct
	s := testToMapStruct{TestField: "b"}
	resultMap, err = PayloadToMap(s)
	r.NoError(err)
	r.Equal(inputMap, resultMap)

	// pass invalid []byte
	resultMap, err = PayloadToMap([]byte("not JSON"))
	r.Error(err)
	r.Contains(err.Error(), "convert to map")
	r.Nil(resultMap)

	// pass invalid structure
	resultMap, err = PayloadToMap(make(chan int))
	r.Error(err)
	r.Contains(err.Error(), "marshal interface[chan int]: json: unsupported type: chan int")
	r.Nil(resultMap)
}

func getValidJSONWebToken() (*JSONWebToken, error) {
	headers := map[string]interface{}{"typ": "JWT", "alg": "EdDSA"}
	claims := map[string]interface{}{"iss": "Albert"}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	signer := NewEd25519Signer(privKey)

	return NewSigned(claims, headers, signer)
}

func getJSONWebTokenWithInvalidPayload() (*JSONWebToken, error) {
	token, err := getValidJSONWebToken()
	if err != nil {
		return nil, err
	}

	// hack the token
	token.Payload = getUnmarshallableMap()

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

func createClaims() *CustomClaim {
	issued := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	expiry := time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC)
	notBefore := time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)

	return &CustomClaim{
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
}

func Test_checkHeaders(t *testing.T) {
	type args struct {
		headers map[string]interface{}
	}

	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "OK",
			args: args{
				headers: map[string]interface{}{
					jose.HeaderAlgorithm:   "EdDSA",
					jose.HeaderType:        "JWT",
					jose.HeaderContentType: "application/example;part=\"1/2\"",
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "OK Explicit type",
			args: args{
				headers: map[string]interface{}{
					jose.HeaderAlgorithm:   "EdDSA",
					jose.HeaderType:        "openid4vci-proof+jwt",
					jose.HeaderContentType: "application/example;part=\"1/2\"",
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "alg missed",
			args: args{
				headers: map[string]interface{}{
					jose.HeaderType:        "JWT",
					jose.HeaderContentType: "application/example;part=\"1/2\"",
				},
			},
			wantErr: assert.Error,
		},
		{
			name: "invalid typ format",
			args: args{
				headers: map[string]interface{}{
					jose.HeaderAlgorithm:   "EdDSA",
					jose.HeaderType:        123,
					jose.HeaderContentType: "application/example;part=\"1/2\"",
				},
			},
			wantErr: assert.Error,
		},
		{
			name: "Explicit type - invalid prefix",
			args: args{
				headers: map[string]interface{}{
					jose.HeaderAlgorithm:   "EdDSA",
					jose.HeaderType:        "jose+json",
					jose.HeaderContentType: "application/example;part=\"1/2\"",
				},
			},
			wantErr: assert.Error,
		},
		{
			name: "invalid typ",
			args: args{
				headers: map[string]interface{}{
					jose.HeaderAlgorithm:   "EdDSA",
					jose.HeaderType:        "jwt",
					jose.HeaderContentType: "application/example;part=\"1/2\"",
				},
			},
			wantErr: assert.Error,
		},
		{
			name: "invalid cty",
			args: args{
				headers: map[string]interface{}{
					jose.HeaderAlgorithm:   "EdDSA",
					jose.HeaderType:        "JWT",
					jose.HeaderContentType: "JWT",
				},
			},
			wantErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wantErr(t, checkHeaders(tt.args.headers), fmt.Sprintf("checkHeaders(%v)", tt.args.headers))
		})
	}
}
