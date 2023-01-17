/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	afgjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
)

const (
	defaultHash     = crypto.SHA256
	defaultSaltSize = 128 / 8

	decoyMinElements = 1
	decoyMaxElements = 4

	year = 365 * 24 * 60 * time.Minute
)

var mr = mathrand.New(mathrand.NewSource(time.Now().Unix())) // nolint:gochecknoglobals

// Claims defines JSON Web Token Claims (https://tools.ietf.org/html/rfc7519#section-4)
type Claims jwt.Claims

// newOpts holds options for creating new SD-JWT.
type newOpts struct {
	Subject string
	ID      string

	Expiry    *jwt.NumericDate
	NotBefore *jwt.NumericDate
	IssuedAt  *jwt.NumericDate

	HolderPublicKey *jwk.JWK

	HashAlg crypto.Hash

	jsonMarshal func(v interface{}) ([]byte, error)
	getSalt     func() (string, error)

	addDecoyDigests bool
}

// NewOpt is the SD-JWT New option.
type NewOpt func(opts *newOpts)

// WithJSONMarshaller is option is for marshalling disclosure.
func WithJSONMarshaller(jsonMarshal func(v interface{}) ([]byte, error)) NewOpt {
	return func(opts *newOpts) {
		opts.jsonMarshal = jsonMarshal
	}
}

// WithSaltFnc is option is for marshalling disclosure.
func WithSaltFnc(fnc func() (string, error)) NewOpt {
	return func(opts *newOpts) {
		opts.getSalt = fnc
	}
}

// WithIssuedAt is an option for SD-JWT payload.
func WithIssuedAt(issuedAt *jwt.NumericDate) NewOpt {
	return func(opts *newOpts) {
		opts.IssuedAt = issuedAt
	}
}

// WithExpiry is an option for SD-JWT payload.
func WithExpiry(expiry *jwt.NumericDate) NewOpt {
	return func(opts *newOpts) {
		opts.Expiry = expiry
	}
}

// WithNotBefore is an option for SD-JWT payload.
func WithNotBefore(notBefore *jwt.NumericDate) NewOpt {
	return func(opts *newOpts) {
		opts.NotBefore = notBefore
	}
}

// WithSubject is an option for SD-JWT payload.
func WithSubject(subject string) NewOpt {
	return func(opts *newOpts) {
		opts.Subject = subject
	}
}

// WithID is an option for SD-JWT payload.
func WithID(id string) NewOpt {
	return func(opts *newOpts) {
		opts.ID = id
	}
}

// WithHolderPublicKey is an option for SD-JWT payload.
func WithHolderPublicKey(jwk *jwk.JWK) NewOpt {
	return func(opts *newOpts) {
		opts.HolderPublicKey = jwk
	}
}

// WithHashAlgorithm is an option for hashing disclosures.
func WithHashAlgorithm(alg crypto.Hash) NewOpt {
	return func(opts *newOpts) {
		opts.HashAlg = alg
	}
}

// WithDecoyDigests is an option for adding decoy digests(default is false).
func WithDecoyDigests(flag bool) NewOpt {
	return func(opts *newOpts) {
		opts.addDecoyDigests = flag
	}
}

// New creates new signed Selective Disclosure JWT based on input claims.
func New(issuer string, claims interface{}, headers jose.Headers,
	signer jose.Signer, opts ...NewOpt) (*SelectiveDisclosureJWT, error) {
	now := time.Now()

	nOpts := &newOpts{
		jsonMarshal: json.Marshal,
		getSalt:     generateSalt,
		HashAlg:     defaultHash,

		// TODO: Discuss with Troy about defaults
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(year)),
	}

	for _, opt := range opts {
		opt(nOpts)
	}

	decoyDisclosures, err := createDecoyDisclosures(nOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create decoy disclosures: %w", err)
	}

	claimsMap, err := afgjwt.PayloadToMap(claims)
	if err != nil {
		return nil, fmt.Errorf("convert payload to map: %w", err)
	}

	disclosures, err := createDisclosures(claimsMap, nOpts)
	if err != nil {
		return nil, err
	}

	digests, err := createDigests(append(disclosures, decoyDisclosures...), nOpts)
	if err != nil {
		return nil, err
	}

	payload := createPayload(issuer, digests, nOpts)

	signedJWT, err := afgjwt.NewSigned(payload, headers, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create SD-JWT from payload[%+v]: %w", payload, err)
	}

	return &SelectiveDisclosureJWT{Disclosures: disclosures, SignedJWT: signedJWT}, nil
}

func createPayload(issuer string, digests []string, nOpts *newOpts) *payload {
	var cnf map[string]interface{}
	if nOpts.HolderPublicKey != nil {
		cnf = make(map[string]interface{})
		cnf["jwk"] = nOpts.HolderPublicKey
	}

	payload := &payload{
		Issuer:    issuer,
		ID:        nOpts.ID,
		Subject:   nOpts.Subject,
		IssuedAt:  nOpts.IssuedAt,
		Expiry:    nOpts.Expiry,
		NotBefore: nOpts.NotBefore,
		CNF:       cnf,
		SD:        digests,
		SDAlg:     strings.ToLower(nOpts.HashAlg.String()),
	}

	return payload
}

func createDigests(disclosures []string, nOpts *newOpts) ([]string, error) {
	var digests []string

	for _, disclosure := range disclosures {
		digest, inErr := common.GetHash(nOpts.HashAlg, disclosure)
		if inErr != nil {
			return nil, fmt.Errorf("hash disclosure: %w", inErr)
		}

		digests = append(digests, digest)
	}

	mr.Shuffle(len(digests), func(i, j int) {
		digests[i], digests[j] = digests[j], digests[i]
	})

	return digests, nil
}

func createDecoyDisclosures(opts *newOpts) ([]string, error) {
	if !opts.addDecoyDigests {
		return nil, nil
	}

	n := mr.Intn(decoyMaxElements-decoyMinElements+1) + decoyMinElements

	var decoyDisclosures []string

	for i := 0; i < n; i++ {
		salt, err := opts.getSalt()
		if err != nil {
			return nil, err
		}

		decoyDisclosures = append(decoyDisclosures, salt)
	}

	return decoyDisclosures, nil
}

// SelectiveDisclosureJWT defines Selective Disclosure JSON Web Token (https://tools.ietf.org/html/rfc7519)
type SelectiveDisclosureJWT struct {
	SignedJWT   *afgjwt.JSONWebToken
	Disclosures []string
}

// DecodeClaims fills input c with claims of a token.
func (j *SelectiveDisclosureJWT) DecodeClaims(c interface{}) error {
	return j.SignedJWT.DecodeClaims(c)
}

// LookupStringHeader makes look up of particular header with string value.
func (j *SelectiveDisclosureJWT) LookupStringHeader(name string) string {
	return j.SignedJWT.LookupStringHeader(name)
}

// Serialize makes (compact) serialization of token.
func (j *SelectiveDisclosureJWT) Serialize(detached bool) (string, error) {
	if j.SignedJWT == nil {
		return "", errors.New("JWS serialization is supported only")
	}

	signedJWT, err := j.SignedJWT.Serialize(detached)
	if err != nil {
		return "", err
	}

	cf := common.CombinedFormatForIssuance{
		SDJWT:       signedJWT,
		Disclosures: j.Disclosures,
	}

	return cf.Serialize(), nil
}

func createDisclosures(claims map[string]interface{}, opts *newOpts) ([]string, error) {
	var disclosures []string

	for key, value := range claims {
		disclosure, err := createDisclosure(key, value, opts)
		if err != nil {
			return nil, fmt.Errorf("create disclosure: %w", err)
		}

		disclosures = append(disclosures, disclosure)
	}

	return disclosures, nil
}

func createDisclosure(key string, value interface{}, opts *newOpts) (string, error) {
	salt, err := opts.getSalt()
	if err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	disclosure := []interface{}{salt, key, value}

	disclosureBytes, err := opts.jsonMarshal(disclosure)
	if err != nil {
		return "", fmt.Errorf("marshal disclosure: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(disclosureBytes), nil
}

func generateSalt() (string, error) {
	salt := make([]byte, defaultSaltSize)

	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	// it is RECOMMENDED to base64url-encode the salt value, producing a string.
	return base64.RawURLEncoding.EncodeToString(salt), nil
}

// payload represents SD-JWT payload.
type payload struct {
	Issuer  string `json:"iss,omitempty"`
	Subject string `json:"sub,omitempty"`
	ID      string `json:"jti,omitempty"`

	Expiry    *jwt.NumericDate `json:"exp,omitempty"`
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *jwt.NumericDate `json:"iat,omitempty"`

	CNF map[string]interface{} `json:"cnf,omitempty"`

	SD    []string `json:"_sd,omitempty"`
	SDAlg string   `json:"_sd_alg,omitempty"`
}