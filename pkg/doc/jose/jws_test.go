/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHeaders_GetKeyID(t *testing.T) {
	kid, ok := Headers{"kid": "key id"}.KeyID()
	require.True(t, ok)
	require.Equal(t, "key id", kid)

	kid, ok = Headers{"kid": 777}.KeyID()
	require.False(t, ok)
	require.Empty(t, kid)

	kid, ok = Headers{}.KeyID()
	require.False(t, ok)
	require.Empty(t, kid)
}

func TestHeaders_GetAlgorithm(t *testing.T) {
	kid, ok := Headers{"alg": "EdDSA"}.Algorithm()
	require.True(t, ok)
	require.Equal(t, "EdDSA", kid)

	kid, ok = Headers{"alg": 777}.Algorithm()
	require.False(t, ok)
	require.Empty(t, kid)

	kid, ok = Headers{}.Algorithm()
	require.False(t, ok)
	require.Empty(t, kid)
}

func TestNewCompositeAlgSignatureVerifier(t *testing.T) {
	verifier := NewCompositeAlgSigVerifier(AlgSignatureVerifier{
		Alg: "EdDSA",
		Verifier: SignatureVerifierFunc(
			func(joseHeaders Headers, payload, signingInput, signature []byte) error {
				return errors.New("signature is invalid")
			},
		),
	})

	err := verifier.Verify(Headers{"alg": "EdDSA"}, nil, nil, nil)
	require.Error(t, err)
	require.EqualError(t, err, "signature is invalid")

	// alg is not defined
	err = verifier.Verify(Headers{}, nil, nil, nil)
	require.Error(t, err)
	require.EqualError(t, err, "'alg' JOSE header is not present")

	// not supported alg
	err = verifier.Verify(Headers{"alg": "RS256"}, nil, nil, nil)
	require.Error(t, err)
	require.EqualError(t, err, "no verifier found for RS256 algorithm")
}

func TestDefaultSigningInputVerifier_Verify(t *testing.T) {
	verifier := DefaultSigningInputVerifier(func(joseHeaders Headers, payload, signingInput, signature []byte) error {
		return errors.New("signature is invalid")
	})

	err := verifier.Verify(Headers{"alg": "EdDSA"}, nil, nil, nil)
	require.Error(t, err)
	require.EqualError(t, err, "signature is invalid")

	// fail in signingInput()
	err = verifier.Verify(Headers{HeaderB64Payload: "invalid value"}, nil, nil, nil)
	require.Error(t, err)
	require.EqualError(t, err, "invalid b64 header")
}

func TestJSONWebSignature_SerializeCompact(t *testing.T) {
	headers := Headers{"alg": "EdSDA", "typ": "JWT"}
	payload := []byte("payload")

	jws, err := NewJWS(headers, nil, payload,
		&testSigner{
			headers:   Headers{"alg": "dummy"},
			signature: []byte("signature"),
		})
	require.NoError(t, err)

	jwsCompact, err := jws.SerializeCompact(false)
	require.NoError(t, err)
	require.NotEmpty(t, jwsCompact)

	// b64=false
	jws, err = NewJWS(headers, nil, payload,
		&testSigner{
			headers:   Headers{"alg": "dummy", "b64": false},
			signature: []byte("signature"),
		})
	require.NoError(t, err)

	jwsCompact, err = jws.SerializeCompact(false)
	require.NoError(t, err)
	require.NotEmpty(t, jwsCompact)

	// signer error
	jws, err = NewJWS(headers, nil, payload,
		&testSigner{
			headers: Headers{"alg": "dummy"},
			err:     errors.New("signer error"),
		})
	require.Error(t, err)
	require.Contains(t, err.Error(), "sign JWS verification data")
	require.Nil(t, jws)

	// no alg defined
	jws, err = NewJWS(Headers{}, nil, payload,
		&testSigner{
			headers: Headers{},
		})
	require.Error(t, err)
	require.Contains(t, err.Error(), "alg JWS header is not defined")
	require.Nil(t, jws)

	// jose headers marshalling error
	jws, err = NewJWS(Headers{}, nil, payload,
		&testSigner{
			headers: getUnmarshallableMap(),
		})
	require.Error(t, err)
	require.Contains(t, err.Error(), "serialize JWS headers")
	require.Nil(t, jws)

	// invalid b64
	jws, err = NewJWS(Headers{}, nil, payload,
		&testSigner{
			headers:   Headers{"alg": "dummy", "b64": "invalid"},
			signature: []byte("signature"),
		})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid b64 header")
	require.Nil(t, jws)
}

func TestJSONWebSignature_Signature(t *testing.T) {
	jws := &JSONWebSignature{
		signature: []byte("signature"),
	}
	require.NotEmpty(t, jws.Signature())

	jws.signature = nil
	require.Empty(t, jws.Signature())
}

func TestParseJWS(t *testing.T) {
	corruptedBased64 := "XXXXXaGVsbG8="

	jws, err := NewJWS(Headers{"alg": "EdSDA", "typ": "JWT"}, nil, []byte("payload"),
		&testSigner{
			headers:   Headers{"alg": "dummy"},
			signature: []byte("signature"),
		})
	require.NoError(t, err)

	jwsCompact, err := jws.SerializeCompact(false)
	require.NoError(t, err)
	require.NotEmpty(t, jwsCompact)

	validJWSParts := strings.Split(jwsCompact, ".")

	parsedJWS, err := ParseJWS(jwsCompact, &testVerifier{})
	require.NoError(t, err)
	require.NotNil(t, parsedJWS)
	require.Equal(t, jws, parsedJWS)

	jwsDetached := fmt.Sprintf("%s.%s.%s", validJWSParts[0], "", validJWSParts[2])

	detachedPayload, err := base64.RawURLEncoding.DecodeString(validJWSParts[1])
	require.NoError(t, err)

	parsedJWS, err = ParseJWS(jwsDetached, &testVerifier{}, WithJWSDetachedPayload(detachedPayload))
	require.NoError(t, err)
	require.NotNil(t, parsedJWS)
	require.Equal(t, jws, parsedJWS)

	// Parse not compact JWS format
	parsedJWS, err = ParseJWS(`{"some": "JSON"}`, &testVerifier{})
	require.Error(t, err)
	require.EqualError(t, err, "JWS JSON serialization is not supported")
	require.Nil(t, parsedJWS)

	// Parse invalid compact JWS format
	parsedJWS, err = ParseJWS("two_parts.only", &testVerifier{})
	require.Error(t, err)
	require.EqualError(t, err, "invalid JWS compact format")
	require.Nil(t, parsedJWS)

	// invalid headers
	jwsWithInvalidHeaders := fmt.Sprintf("%s.%s.%s", "invalid", validJWSParts[1], validJWSParts[2])
	parsedJWS, err = ParseJWS(jwsWithInvalidHeaders, &testVerifier{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unmarshal JSON headers")
	require.Nil(t, parsedJWS)

	jwsWithInvalidHeaders = fmt.Sprintf("%s.%s.%s", corruptedBased64, validJWSParts[1], validJWSParts[2])
	parsedJWS, err = ParseJWS(jwsWithInvalidHeaders, &testVerifier{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode base64 header")
	require.Nil(t, parsedJWS)

	emptyHeaders := base64.RawURLEncoding.EncodeToString([]byte("{}"))

	jwsWithInvalidHeaders = fmt.Sprintf("%s.%s.%s", emptyHeaders, validJWSParts[1], validJWSParts[2])
	parsedJWS, err = ParseJWS(jwsWithInvalidHeaders, &testVerifier{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "alg JWS header is not defined")
	require.Nil(t, parsedJWS)

	// invalid payload
	jwsWithInvalidPayload := fmt.Sprintf("%s.%s.%s", validJWSParts[0], corruptedBased64, validJWSParts[2])
	parsedJWS, err = ParseJWS(jwsWithInvalidPayload, &testVerifier{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode base64 payload")
	require.Nil(t, parsedJWS)

	// invalid signature
	jwsWithInvalidSignature := fmt.Sprintf("%s.%s.%s", validJWSParts[0], validJWSParts[1], corruptedBased64)
	parsedJWS, err = ParseJWS(jwsWithInvalidSignature, &testVerifier{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode base64 signature")
	require.Nil(t, parsedJWS)

	// verifier error
	parsedJWS, err = ParseJWS(jwsCompact, &testVerifier{err: errors.New("bad signature")})
	require.Error(t, err)
	require.EqualError(t, err, "bad signature")
	require.Nil(t, parsedJWS)
}

func TestIsCompactJWS(t *testing.T) {
	require.True(t, IsCompactJWS("a.b.c"))
	require.False(t, IsCompactJWS("a.b"))
	require.False(t, IsCompactJWS(`{"some": "JSON"}`))
	require.False(t, IsCompactJWS(""))
}

type testSigner struct {
	headers   Headers
	signature []byte
	err       error
}

func (s testSigner) Sign(_ []byte) ([]byte, error) {
	return s.signature, s.err
}

func (s testSigner) Headers() Headers {
	return s.headers
}

type testVerifier struct {
	err error
}

func (v testVerifier) Verify(_ Headers, _, _, _ []byte) error {
	return v.err
}

func getUnmarshallableMap() map[string]interface{} {
	return map[string]interface{}{"alg": "JWS", "error": map[chan int]interface{}{make(chan int): 6}}
}
