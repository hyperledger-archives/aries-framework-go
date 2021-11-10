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

	"github.com/square/go-jose/v3/json"
)

const (
	jwsPartsCount    = 3
	jwsHeaderPart    = 0
	jwsPayloadPart   = 1
	jwsSignaturePart = 2
)

// JSONWebSignature defines JSON Web Signature (https://tools.ietf.org/html/rfc7515)
type JSONWebSignature struct {
	ProtectedHeaders   Headers
	UnprotectedHeaders Headers
	Payload            []byte

	signature   []byte
	joseHeaders Headers
}

// SignatureVerifier makes verification of JSON Web Signature.
type SignatureVerifier interface {
	// Verify verifies JWS based on the signing input.
	Verify(joseHeaders Headers, payload, signingInput, signature []byte) error
}

// SignatureVerifierFunc is a function wrapper for SignatureVerifier.
type SignatureVerifierFunc func(joseHeaders Headers, payload, signingInput, signature []byte) error

// Verify verifies JWS signature.
func (s SignatureVerifierFunc) Verify(joseHeaders Headers, payload, signingInput, signature []byte) error {
	return s(joseHeaders, payload, signingInput, signature)
}

// DefaultSigningInputVerifier is a SignatureVerifier that generates the signing input
// from the given headers and payload, instead of using the signing input parameter.
type DefaultSigningInputVerifier func(joseHeaders Headers, payload, signingInput, signature []byte) error

// Verify verifies JWS signature.
func (s DefaultSigningInputVerifier) Verify(joseHeaders Headers, payload, _, signature []byte) error {
	signingInputData, err := signingInput(joseHeaders, payload)
	if err != nil {
		return err
	}

	return s(joseHeaders, payload, signingInputData, signature)
}

// CompositeAlgSigVerifier defines composite signature verifier based on the algorithm
// taken from JOSE header alg.
type CompositeAlgSigVerifier struct {
	verifierByAlg map[string]SignatureVerifier
}

// AlgSignatureVerifier defines verifier for particular signature algorithm.
type AlgSignatureVerifier struct {
	Alg      string
	Verifier SignatureVerifier
}

// NewCompositeAlgSigVerifier creates a new CompositeAlgSigVerifier.
func NewCompositeAlgSigVerifier(v AlgSignatureVerifier, vOther ...AlgSignatureVerifier) *CompositeAlgSigVerifier {
	verifierByAlg := make(map[string]SignatureVerifier, 1+len(vOther))
	verifierByAlg[v.Alg] = v.Verifier

	for _, v := range vOther {
		verifierByAlg[v.Alg] = v.Verifier
	}

	return &CompositeAlgSigVerifier{
		verifierByAlg: verifierByAlg,
	}
}

// Verify verifiers JWS signature.
func (v *CompositeAlgSigVerifier) Verify(joseHeaders Headers, payload, signingInput, signature []byte) error {
	alg, ok := joseHeaders.Algorithm()
	if !ok {
		return errors.New("'alg' JOSE header is not present")
	}

	verifier, ok := v.verifierByAlg[alg]
	if !ok {
		return fmt.Errorf("no verifier found for %s algorithm", alg)
	}

	return verifier.Verify(joseHeaders, payload, signingInput, signature)
}

// Signer defines JWS Signer interface. It makes signing of data and provides custom JWS headers relevant to the signer.
type Signer interface {
	// Sign signs.
	Sign(data []byte) ([]byte, error)

	// Headers provides JWS headers. "alg" header must be provided (see https://tools.ietf.org/html/rfc7515#section-4.1)
	Headers() Headers
}

// NewJWS creates JSON Web Signature.
func NewJWS(protectedHeaders, unprotectedHeaders Headers, payload []byte, signer Signer) (*JSONWebSignature, error) {
	headers := mergeHeaders(protectedHeaders, signer.Headers())
	jws := &JSONWebSignature{
		ProtectedHeaders:   headers,
		UnprotectedHeaders: unprotectedHeaders,
		Payload:            payload,
		joseHeaders:        headers,
	}

	signature, err := sign(jws.joseHeaders, payload, signer)
	if err != nil {
		return nil, fmt.Errorf("sign JWS: %w", err)
	}

	jws.signature = signature

	return jws, nil
}

// SerializeCompact makes JWS Compact Serialization (https://tools.ietf.org/html/rfc7515#section-7.1)
func (s JSONWebSignature) SerializeCompact(detached bool) (string, error) {
	byteHeaders, err := json.Marshal(s.joseHeaders)
	if err != nil {
		return "", fmt.Errorf("marshal JWS JOSE Headers: %w", err)
	}

	b64Headers := base64.RawURLEncoding.EncodeToString(byteHeaders)

	b64Payload := ""
	if !detached {
		b64Payload = base64.RawURLEncoding.EncodeToString(s.Payload)
	}

	b64Signature := base64.RawURLEncoding.EncodeToString(s.signature)

	return fmt.Sprintf("%s.%s.%s",
		b64Headers,
		b64Payload,
		b64Signature), nil
}

// Signature returns a copy of JWS signature.
func (s JSONWebSignature) Signature() []byte {
	if s.signature == nil {
		return nil
	}

	sCopy := make([]byte, len(s.signature))
	copy(sCopy, s.signature)

	return sCopy
}

func mergeHeaders(h1, h2 Headers) Headers {
	h := make(Headers, len(h1)+len(h2))

	for k, v := range h2 {
		h[k] = v
	}

	for k, v := range h1 {
		h[k] = v
	}

	return h
}

func sign(joseHeaders Headers, payload []byte, signer Signer) ([]byte, error) {
	err := checkJWSHeaders(joseHeaders)
	if err != nil {
		return nil, fmt.Errorf("check JOSE headers: %w", err)
	}

	sigInput, err := signingInput(joseHeaders, payload)
	if err != nil {
		return nil, fmt.Errorf("prepare JWS verification data: %w", err)
	}

	signature, err := signer.Sign(sigInput)
	if err != nil {
		return nil, fmt.Errorf("sign JWS verification data: %w", err)
	}

	return signature, nil
}

// jwsParseOpts holds options for the JWS Parsing.
type jwsParseOpts struct {
	detachedPayload []byte
}

// JWSParseOpt is the JWS Parser option.
type JWSParseOpt func(opts *jwsParseOpts)

// WithJWSDetachedPayload option is for definition of JWS detached payload.
func WithJWSDetachedPayload(payload []byte) JWSParseOpt {
	return func(opts *jwsParseOpts) {
		opts.detachedPayload = payload
	}
}

// ParseJWS parses serialized JWS. Currently only JWS Compact Serialization parsing is supported.
func ParseJWS(jws string, verifier SignatureVerifier, opts ...JWSParseOpt) (*JSONWebSignature, error) {
	pOpts := &jwsParseOpts{}

	for _, opt := range opts {
		opt(pOpts)
	}

	if strings.HasPrefix(jws, "{") {
		// TODO support JWS JSON serialization format
		//  https://github.com/hyperledger/aries-framework-go/issues/1331
		return nil, errors.New("JWS JSON serialization is not supported")
	}

	return parseCompacted(jws, verifier, pOpts)
}

// IsCompactJWS checks weather input is a compact JWS (based on https://tools.ietf.org/html/rfc7516#section-9)
func IsCompactJWS(s string) bool {
	parts := strings.Split(s, ".")

	return len(parts) == jwsPartsCount
}

func parseCompacted(jwsCompact string, verifier SignatureVerifier, opts *jwsParseOpts) (*JSONWebSignature, error) {
	parts := strings.Split(jwsCompact, ".")
	if len(parts) != jwsPartsCount {
		return nil, errors.New("invalid JWS compact format")
	}

	joseHeaders, err := parseCompactedHeaders(parts)
	if err != nil {
		return nil, err
	}

	payload, err := parseCompactedPayload(parts[jwsPayloadPart], opts)
	if err != nil {
		return nil, err
	}

	sInput, err := signingInput(joseHeaders, payload)
	if err != nil {
		return nil, fmt.Errorf("build signing input: %w", err)
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[jwsSignaturePart])
	if err != nil {
		return nil, fmt.Errorf("decode base64 signature: %w", err)
	}

	err = verifier.Verify(joseHeaders, payload, sInput, signature)
	if err != nil {
		return nil, err
	}

	return &JSONWebSignature{
		ProtectedHeaders: joseHeaders,
		Payload:          payload,
		signature:        signature,
		joseHeaders:      joseHeaders,
	}, nil
}

func parseCompactedPayload(jwsPayload string, opts *jwsParseOpts) ([]byte, error) {
	if len(opts.detachedPayload) > 0 {
		return opts.detachedPayload, nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(jwsPayload)
	if err != nil {
		return nil, fmt.Errorf("decode base64 payload: %w", err)
	}

	return payload, nil
}

func parseCompactedHeaders(parts []string) (Headers, error) {
	headersBytes, err := base64.RawURLEncoding.DecodeString(parts[jwsHeaderPart])
	if err != nil {
		return nil, fmt.Errorf("decode base64 header: %w", err)
	}

	var joseHeaders Headers

	err = json.Unmarshal(headersBytes, &joseHeaders)
	if err != nil {
		return nil, fmt.Errorf("unmarshal JSON headers: %w", err)
	}

	err = checkJWSHeaders(joseHeaders)
	if err != nil {
		return nil, err
	}

	return joseHeaders, nil
}

func signingInput(headers Headers, payload []byte) ([]byte, error) {
	headersBytes, err := json.Marshal(headers)
	if err != nil {
		return nil, fmt.Errorf("serialize JWS headers: %w", err)
	}

	hBase64 := true

	if b64, ok := headers[HeaderB64Payload]; ok {
		if hBase64, ok = b64.(bool); !ok {
			return nil, errors.New("invalid b64 header")
		}
	}

	headersStr := base64.RawURLEncoding.EncodeToString(headersBytes)

	var payloadStr string

	if hBase64 {
		payloadStr = base64.RawURLEncoding.EncodeToString(payload)
	} else {
		payloadStr = string(payload)
	}

	return []byte(fmt.Sprintf("%s.%s", headersStr, payloadStr)), nil
}

func checkJWSHeaders(headers Headers) error {
	if _, ok := headers[HeaderAlgorithm]; !ok {
		return fmt.Errorf("%s JWS header is not defined", HeaderAlgorithm)
	}

	return nil
}

func convertMapToValue(vOriginToBeMap, vDest interface{}) error {
	if _, ok := vOriginToBeMap.(map[string]interface{}); !ok {
		return errors.New("expected value to be a map")
	}

	mBytes, err := json.Marshal(vOriginToBeMap)
	if err != nil {
		return err
	}

	return json.Unmarshal(mBytes, vDest)
}
