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
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	afgjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
)

const (
	defaultHash     = crypto.SHA256
	defaultSaltSize = 28

	year = 365 * 24 * 60 * time.Minute
)

// Claims defines JSON Web Token Claims (https://tools.ietf.org/html/rfc7519#section-4)
type Claims jwt.Claims

// newOpts holds options for creating new SD-JWT.
type newOpts struct {
	Subject string
	ID      string

	Expiry    *jwt.NumericDate
	NotBefore *jwt.NumericDate
	IssuedAt  *jwt.NumericDate

	HashAlg crypto.Hash

	jsonMarshal func(v interface{}) ([]byte, error)
	getSalt     func() (string, error)
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

// WithHashAlgorithm is an option for hashing disclosures.
func WithHashAlgorithm(alg crypto.Hash) NewOpt {
	return func(opts *newOpts) {
		opts.HashAlg = alg
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

	claimsMap, err := afgjwt.PayloadToMap(claims)
	if err != nil {
		return nil, err
	}

	disclosures, err := createDisclosures(claimsMap, nOpts)
	if err != nil {
		return nil, err
	}

	var hashedDisclosures []string

	for _, disclosure := range disclosures {
		hashedDisclosure, inErr := common.GetHash(nOpts.HashAlg, disclosure)
		if inErr != nil {
			return nil, fmt.Errorf("hash disclosure: %w", inErr)
		}

		hashedDisclosures = append(hashedDisclosures, hashedDisclosure)
	}

	payload := &common.Payload{
		Issuer:    issuer,
		ID:        nOpts.ID,
		Subject:   nOpts.Subject,
		IssuedAt:  nOpts.IssuedAt,
		Expiry:    nOpts.Expiry,
		NotBefore: nOpts.NotBefore,
		SD:        hashedDisclosures,
		SDAlg:     strings.ToLower(nOpts.HashAlg.String()),
	}

	signedJWT, err := afgjwt.NewSigned(payload, headers, signer)
	if err != nil {
		return nil, err
	}

	return &SelectiveDisclosureJWT{Disclosures: disclosures, SignedJWT: signedJWT}, nil
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

	combinedFormatForPresentation := signedJWT
	for _, disclosure := range j.Disclosures {
		combinedFormatForPresentation += common.DisclosureSeparator + disclosure
	}

	return combinedFormatForPresentation, nil
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

	return string(salt), nil
}
