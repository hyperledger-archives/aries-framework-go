/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"

	"github.com/square/go-jose/v3/json"
	"github.com/square/go-jose/v3/jwt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
)

const (
	// TypeJWT defines JWT type
	TypeJWT = "JWT"

	// AlgorithmNone used to indicate unsecured JWT
	AlgorithmNone = "none"
)

// Claims defines JSON Web Token Claims (https://tools.ietf.org/html/rfc7519#section-4)
type Claims jwt.Claims

// jwtParseOpts holds options for the JWT parsing.
type parseOpts struct {
	detachedPayload []byte
	sigVerifier     jose.SignatureVerifier
}

// ParseOpt is the JWT Parser option.
type ParseOpt func(opts *parseOpts)

// WithJWTDetachedPayload option is for definition of JWT detached payload.
func WithJWTDetachedPayload(payload []byte) ParseOpt {
	return func(opts *parseOpts) {
		opts.detachedPayload = payload
	}
}

// WithSignatureVerifier option is for definition of JWT detached payload.
func WithSignatureVerifier(signatureVerifier jose.SignatureVerifier) ParseOpt {
	return func(opts *parseOpts) {
		opts.sigVerifier = signatureVerifier
	}
}

type signatureVerifierFunc func(joseHeaders jose.Headers, payload, signingInput, signature []byte) error

func (v signatureVerifierFunc) Verify(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
	return v(joseHeaders, payload, signingInput, signature)
}

func verifyUnsecuredJWT(joseHeaders jose.Headers, _, _, signature []byte) error {
	alg, ok := joseHeaders.Algorithm()
	if !ok {
		return errors.New("alg is not defined")
	}

	if alg != AlgorithmNone {
		return errors.New("alg value is not 'none'")
	}

	if len(signature) > 0 {
		return errors.New("not empty signature")
	}

	return nil
}

// UnsecuredJWTVerifier provides verifier for unsecured JWT.
func UnsecuredJWTVerifier() jose.SignatureVerifier {
	return signatureVerifierFunc(verifyUnsecuredJWT)
}

type unsecuredJWTSigner struct {
	extraHeaders map[string]interface{}
}

func (s unsecuredJWTSigner) Sign(_ []byte) ([]byte, error) {
	return []byte(""), nil
}

func (s unsecuredJWTSigner) Headers() jose.Headers {
	jHeaders := map[string]interface{}{
		jose.HeaderAlgorithm: AlgorithmNone,
		jose.HeaderType:      TypeJWT,
	}

	for k, v := range s.extraHeaders {
		if _, ok := jHeaders[k]; !ok {
			jHeaders[k] = v
		}
	}

	return jHeaders
}

// JSONWebToken defines JSON Web Token (https://tools.ietf.org/html/rfc7519)
type JSONWebToken struct {
	Headers jose.Headers

	Payload map[string]interface{}

	signature []byte
}

// Parse parses input JWT in serialized form into JSON Web Token.
// Currently JWS and unsecured JWT is supported.9
func Parse(jwtSerialized string, opts ...ParseOpt) (*JSONWebToken, error) {
	if !jose.IsCompactJWS(jwtSerialized) {
		return nil, errors.New("JWT of compacted JWS form is supported only")
	}

	pOpts := &parseOpts{}

	for _, opt := range opts {
		opt(pOpts)
	}

	return parseJWS(jwtSerialized, pOpts)
}

// DecodeClaims fills input c with claims of a token.
func (j *JSONWebToken) DecodeClaims(c interface{}) error {
	pBytes, err := json.Marshal(j.Payload)
	if err != nil {
		return err
	}

	return json.Unmarshal(pBytes, c)
}

// LookupStringHeader makes look up of particular header with string value.
func (j *JSONWebToken) LookupStringHeader(name string) string {
	if headerValue, ok := j.Headers[name]; ok {
		if headerStrValue, ok := headerValue.(string); ok {
			return headerStrValue
		}
	}

	return ""
}

// SerializeSigned makes (compact) serialization of token.
func (j *JSONWebToken) SerializeSigned(signer jose.Signer, detached bool) (string, error) {
	return j.serialize(signer, detached)
}

// SerializeUnsecured build unsecured JWT.
func (j *JSONWebToken) SerializeUnsecured(extraHeaders map[string]interface{}, detached bool) (string, error) {
	return j.serialize(&unsecuredJWTSigner{extraHeaders}, detached)
}

func (j *JSONWebToken) serialize(signer jose.Signer, detached bool) (string, error) {
	payloadBytes, err := j.marshalPayload()
	if err != nil {
		return "", fmt.Errorf("marshal JWT claims: %w", err)
	}

	// JWS compact serialization uses only protected headers (https://tools.ietf.org/html/rfc7515#section-3.1).
	jws, err := jose.NewJWS(j.Headers, nil, payloadBytes, signer)
	if err != nil {
		return "", err
	}

	j.signature = jws.Signature()

	return jws.SerializeCompact(detached)
}

func (j *JSONWebToken) marshalPayload() ([]byte, error) {
	return json.Marshal(j.Payload)
}

func parseJWS(jwtSerialized string, opts *parseOpts) (*JSONWebToken, error) {
	jwsOpts := make([]jose.JWSParseOpt, 0)

	if opts.detachedPayload != nil {
		jwsOpts = append(jwsOpts, jose.WithJWSDetachedPayload(opts.detachedPayload))
	}

	jws, err := jose.ParseJWS(jwtSerialized, opts.sigVerifier, jwsOpts...)
	if err != nil {
		return nil, fmt.Errorf("parse JWT from compact JWS: %w", err)
	}

	return mapJWSToJWT(jws)
}

func mapJWSToJWT(jws *jose.JSONWebSignature) (*JSONWebToken, error) {
	headers := jws.ProtectedHeaders

	err := checkHeaders(headers)
	if err != nil {
		return nil, fmt.Errorf("check JWT headers: %w", err)
	}

	claims, err := toMap(jws.Payload)
	if err != nil {
		return nil, fmt.Errorf("read JWT claims from JWS payload: %w", err)
	}

	return &JSONWebToken{
		Headers:   headers,
		Payload:   claims,
		signature: jws.Signature(),
	}, nil
}

// New creates new JSON Web Token based on input claims.
func New(claims interface{}) (*JSONWebToken, error) {
	m, err := toMap(claims)
	if err != nil {
		return nil, fmt.Errorf("unmarshallable claims: %w", err)
	}

	return &JSONWebToken{
		Payload: m,
	}, nil
}

func checkHeaders(headers map[string]interface{}) error {
	if _, ok := headers[jose.HeaderAlgorithm]; !ok {
		return errors.New("alg header is not defined")
	}

	typ, ok := headers[jose.HeaderType]
	if ok && typ != TypeJWT {
		return errors.New("typ is not JWT")
	}

	cty, ok := headers[jose.HeaderContentType]
	if ok && cty == TypeJWT { // https://tools.ietf.org/html/rfc7519#section-5.2
		return errors.New("nested JWT is not supported")
	}

	return nil
}

func toMap(i interface{}) (map[string]interface{}, error) {
	if reflect.ValueOf(i).Kind() == reflect.Map {
		return i.(map[string]interface{}), nil
	}

	var (
		b   []byte
		err error
	)

	switch cv := i.(type) {
	case []byte:
		b = cv
	case string:
		b = []byte(cv)
	default:
		b, err = json.Marshal(i)
		if err != nil {
			return nil, fmt.Errorf("convert to bytes: ")
		}
	}

	var m map[string]interface{}

	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()

	if err := d.Decode(&m); err != nil {
		return nil, fmt.Errorf("convert to map: %v", err)
	}

	return m, nil
}
