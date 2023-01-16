/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-jose/go-jose/v3/json"
	"github.com/go-jose/go-jose/v3/jwt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
)

const (
	// TypeJWT defines JWT type.
	TypeJWT = "JWT"

	// AlgorithmNone used to indicate unsecured JWT.
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

type unsecuredJWTSigner struct{}

func (s unsecuredJWTSigner) Sign(_ []byte) ([]byte, error) {
	return []byte(""), nil
}

func (s unsecuredJWTSigner) Headers() jose.Headers {
	return map[string]interface{}{
		jose.HeaderAlgorithm: AlgorithmNone,
	}
}

// JSONWebToken defines JSON Web Token (https://tools.ietf.org/html/rfc7519)
type JSONWebToken struct {
	Headers jose.Headers

	Payload map[string]interface{}

	jws *jose.JSONWebSignature
}

// Parse parses input JWT in serialized form into JSON Web Token.
// Currently JWS and unsecured JWT is supported.
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

// Serialize makes (compact) serialization of token.
func (j *JSONWebToken) Serialize(detached bool) (string, error) {
	if j.jws == nil {
		return "", errors.New("JWS serialization is supported only")
	}

	return j.jws.SerializeCompact(detached)
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

	claims, err := PayloadToMap(jws.Payload)
	if err != nil {
		return nil, fmt.Errorf("read JWT claims from JWS payload: %w", err)
	}

	return &JSONWebToken{
		Headers: headers,
		Payload: claims,
		jws:     jws,
	}, nil
}

// NewSigned creates new signed JSON Web Token based on input claims.
func NewSigned(claims interface{}, headers jose.Headers, signer jose.Signer) (*JSONWebToken, error) {
	return newSigned(claims, headers, signer)
}

// NewUnsecured creates new unsecured JSON Web Token based on input claims.
func NewUnsecured(claims interface{}, headers jose.Headers) (*JSONWebToken, error) {
	return newSigned(claims, headers, &unsecuredJWTSigner{})
}

func newSigned(claims interface{}, headers jose.Headers, signer jose.Signer) (*JSONWebToken, error) {
	payloadMap, err := PayloadToMap(claims)
	if err != nil {
		return nil, fmt.Errorf("unmarshallable claims: %w", err)
	}

	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("marshal JWT claims: %w", err)
	}

	// JWS compact serialization uses only protected headers (https://tools.ietf.org/html/rfc7515#section-3.1).
	jws, err := jose.NewJWS(headers, nil, payloadBytes, signer)
	if err != nil {
		return nil, fmt.Errorf("create JWS: %w", err)
	}

	return &JSONWebToken{
		Headers: jws.ProtectedHeaders,
		Payload: payloadMap,
		jws:     jws,
	}, nil
}

// IsJWS checks if JWT is a JWS of valid structure.
func IsJWS(s string) bool {
	parts := strings.Split(s, ".")

	return len(parts) == 3 &&
		isValidJSON(parts[0]) &&
		isValidJSON(parts[1]) &&
		parts[2] != ""
}

// IsJWTUnsecured checks if JWT is an unsecured JWT of valid structure.
func IsJWTUnsecured(s string) bool {
	parts := strings.Split(s, ".")

	return len(parts) == 3 &&
		isValidJSON(parts[0]) &&
		isValidJSON(parts[1]) &&
		parts[2] == ""
}

func isValidJSON(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return false
	}

	var j map[string]interface{}
	err = json.Unmarshal(b, &j)

	return err == nil
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

// PayloadToMap transforms interface to map.
func PayloadToMap(i interface{}) (map[string]interface{}, error) {
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
			return nil, fmt.Errorf("marshal interface[%T]: %w", i, err)
		}
	}

	var m map[string]interface{}

	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()

	if err := d.Decode(&m); err != nil {
		return nil, fmt.Errorf("convert to map: %w", err)
	}

	return m, nil
}
