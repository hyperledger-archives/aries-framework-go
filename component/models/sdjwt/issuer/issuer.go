/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

/*
Package issuer enables the Issuer: An entity that creates SD-JWTs.

An SD-JWT is a digitally signed document containing digests over the claims
(per claim: a random salt, the claim name and the claim value).
It MAY further contain clear-text claims that are always disclosed to the Verifier.
It MUST be digitally signed using the Issuer's private key.

	SD-JWT-DOC = (METADATA, SD-CLAIMS, NON-SD-CLAIMS)
	SD-JWT = SD-JWT-DOC | SIG(SD-JWT-DOC, ISSUER-PRIV-KEY)

SD-CLAIMS is an array of digest values that ensure the integrity of
and map to the respective Disclosures.  Digest values are calculated
over the Disclosures, each of which contains the claim name (CLAIM-NAME),
the claim value (CLAIM-VALUE), and a random salt (SALT).
Digests are calculated using a hash function:

SD-CLAIMS = (
HASH(SALT, CLAIM-NAME, CLAIM-VALUE)
)*

SD-CLAIMS can also be nested deeper to capture more complex objects.

The Issuer further creates a set of Disclosures for all claims in the
SD-JWT. The Disclosures are sent to the Holder together with the SD-JWT:

DISCLOSURES = (
(SALT, CLAIM-NAME, CLAIM-VALUE)
)*

The SD-JWT and the Disclosures are sent to the Holder by the Issuer:

COMBINED-ISSUANCE = SD-JWT | DISCLOSURES
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

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"

	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	jsonutil "github.com/hyperledger/aries-framework-go/component/models/util/json"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

const (
	defaultHash = crypto.SHA256

	decoyMinElements = 1
	decoyMaxElements = 4

	credentialSubjectKey = "credentialSubject"
	vcKey                = "vc"
)

var mr = mathrand.New(mathrand.NewSource(time.Now().Unix())) // nolint:gochecknoglobals

// Claims defines JSON Web Token Claims (https://tools.ietf.org/html/rfc7519#section-4)
type Claims jwt.Claims

// newOpts holds options for creating new SD-JWT.
type newOpts struct {
	Subject  string
	Audience string
	JTI      string
	ID       string

	Expiry    *jwt.NumericDate
	NotBefore *jwt.NumericDate
	IssuedAt  *jwt.NumericDate

	HolderPublicKey *jwk.JWK

	HashAlg crypto.Hash

	jsonMarshal func(v interface{}) ([]byte, error)
	getSalt     func() (string, error)

	addDecoyDigests  bool
	structuredClaims bool

	nonSDClaimsMap    map[string]bool
	version           common.SDJWTVersion
	alwaysInclude     map[string]bool
	recursiveClaimMap map[string]bool
}

// NewOpt is the SD-JWT New option.
type NewOpt func(opts *newOpts)

// WithSDJWTVersion sets version for SD-JWT VC.
func WithSDJWTVersion(version common.SDJWTVersion) NewOpt {
	return func(opts *newOpts) {
		opts.version = version
	}
}

// WithJSONMarshaller is option is for marshalling disclosure.
func WithJSONMarshaller(jsonMarshal func(v interface{}) ([]byte, error)) NewOpt {
	return func(opts *newOpts) {
		opts.jsonMarshal = jsonMarshal
	}
}

// WithSaltFnc is an option for generating salt. Mostly used for testing.
// A new salt MUST be chosen for each claim independently of other salts.
// The RECOMMENDED minimum length of the randomly-generated portion of the salt is 128 bits.
// It is RECOMMENDED to base64url-encode the salt value, producing a string.
func WithSaltFnc(fnc func() (string, error)) NewOpt {
	return func(opts *newOpts) {
		opts.getSalt = fnc
	}
}

// WithIssuedAt is an option for SD-JWT payload. This is a clear-text claim that is always disclosed.
func WithIssuedAt(issuedAt *jwt.NumericDate) NewOpt {
	return func(opts *newOpts) {
		opts.IssuedAt = issuedAt
	}
}

// WithAudience is an option for SD-JWT payload. This is a clear-text claim that is always disclosed.
func WithAudience(audience string) NewOpt {
	return func(opts *newOpts) {
		opts.Audience = audience
	}
}

// WithExpiry is an option for SD-JWT payload. This is a clear-text claim that is always disclosed.
func WithExpiry(expiry *jwt.NumericDate) NewOpt {
	return func(opts *newOpts) {
		opts.Expiry = expiry
	}
}

// WithNotBefore is an option for SD-JWT payload. This is a clear-text claim that is always disclosed.
func WithNotBefore(notBefore *jwt.NumericDate) NewOpt {
	return func(opts *newOpts) {
		opts.NotBefore = notBefore
	}
}

// WithSubject is an option for SD-JWT payload. This is a clear-text claim that is always disclosed.
func WithSubject(subject string) NewOpt {
	return func(opts *newOpts) {
		opts.Subject = subject
	}
}

// WithJTI is an option for SD-JWT payload. This is a clear-text claim that is always disclosed.
func WithJTI(jti string) NewOpt {
	return func(opts *newOpts) {
		opts.JTI = jti
	}
}

// WithID is an option for SD-JWT payload. This is a clear-text claim that is always disclosed.
func WithID(id string) NewOpt {
	return func(opts *newOpts) {
		opts.ID = id
	}
}

// WithHolderPublicKey is an option for SD-JWT payload.
// The Holder can prove legitimate possession of an SD-JWT by proving control over the same private key during
// the issuance and presentation. An SD-JWT with Holder Binding contains a public key or a reference to a public key
// that matches to the private key controlled by the Holder.
// The "cnf" claim value MUST represent only a single proof-of-possession key. This implementation is using CNF "jwk".
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

// WithStructuredClaims is an option for handling structured claims(default is false).
func WithStructuredClaims(flag bool) NewOpt {
	return func(opts *newOpts) {
		opts.structuredClaims = flag
	}
}

// WithNonSelectivelyDisclosableClaims is an option for provide claim names that should be ignored when creating
// selectively disclosable claims.
// For example if you would like to not selectively disclose id and degree type from the following claims:
// {
//
//	"degree": {
//	   "degree": "MIT",
//	   "type": "BachelorDegree",
//	 },
//	 "name": "Jayden Doe",
//	 "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
//	}
//
// you should specify the following array: []string{"id", "degree.type"}.
func WithNonSelectivelyDisclosableClaims(nonSDClaims []string) NewOpt {
	return func(opts *newOpts) {
		opts.nonSDClaimsMap = common.SliceToMap(nonSDClaims)
	}
}

// WithAlwaysIncludeObjects is an option for provide object keys that should be a part of
// selectively disclosable claims.
// Eexample if you would like to keep original claims structure from example below, but selectively disclose all claims
//
//	{
//		"degree": {
//		   "degree": "MIT",
//		   "type": "BachelorDegree",
//		 },
//		 "name": "Jayden Doe",
//		 "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
//		}
//
// you should specify the following array: []string{"degree"}.
// As output, you will receive:
//
//	{
//		"_sd": [
//			"zDSZ9PKx_bB2CrFU8Xd__LkpMip06ApY-V6Y9fnppuo",
//			"5Hnqg9PgQ4MdHxTv2KDt9qp8ILd1JEYq0luNO8JZ7G4"
//		],
//		"degree": {
//			"_sd": [
//				"i03SehlKmaFrwPM-gX8s3XuF_LTTE2T1XQQSJXjo6pw",
//				"qZEZR8g_uc8fMyQCvs4DjXdY8uOI9IHpOokzx0cH_Qw"
//			]
//		}
//	}
func WithAlwaysIncludeObjects(alwaysIncludeObjects []string) NewOpt {
	return func(opts *newOpts) {
		opts.alwaysInclude = common.SliceToMap(alwaysIncludeObjects)
	}
}

// WithRecursiveClaimsObjects is an option for provide object keys that should be selective disclosed recursively, e.g.
// output digest for given object will refer to the disclosure, that contains digests of nested claims.
// For example if you would like to define degree object as selective disclosed recursively
//
//	{
//		"degree": {
//		   "degree": "MIT",
//		   "type": "BachelorDegree",
//		 },
//		 "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
//	}
//
// you should specify the following array: []string{"degree"}.
// As output, you will receive:
//
//	{
//			"_sd": [
//				"fgoQstuIzTLQ4zqosjUC_qCk-xx3wjDQU2QkQtbn7FI",
//				"mdephPRizMUa-LLs3JVeuTRS0tPaTd0faHg5kgKHNGk"
//			]
//	}
//
// and 4 disclosures:
// nolint:lll
// [
//
//	{
//		"Result": "WyJ2Y2g2YXVDVEo3bGdWWjFxNjN3cWF3IiwiZGVncmVlIix7Il9zZCI6WyJnZnNlcUhtTml0SXUwLTBoMTR5bnFNenV2cTFFaXJUQXpVaERuRWxTVlgwIiwiNDNoZm5NN1N6WnNhbEFkYlhReXE3dzRVdmQ1M1lPeFRORnBGSnI0WkcwQSJdfV0",
//		"Salt": "vch6auCTJ7lgVZ1q63wqaw",
//		"Key": "degree",
//		"Value": {
//			"_sd": [
//				"gfseqHmNitIu0-0h14ynqMzuvq1EirTAzUhDnElSVX0",
//				"43hfnM7SzZsalAdbXQyq7w4Uvd53YOxTNFpFJr4ZG0A"
//			]
//		},
//		"DebugStr": "[\"vch6auCTJ7lgVZ1q63wqaw\",\"degree\",{\"_sd\":[\"gfseqHmNitIu0-0h14ynqMzuvq1EirTAzUhDnElSVX0\",\"43hfnM7SzZsalAdbXQyq7w4Uvd53YOxTNFpFJr4ZG0A\"]}]",
//		"DebugDigest": "mdephPRizMUa-LLs3JVeuTRS0tPaTd0faHg5kgKHNGk"
//	},
//	{
//		"Result": "WyJaVHFiUzI0ZWlybmpQMFlObmFmakxRIiwiaWQiLCJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiXQ",
//		"Salt": "ZTqbS24eirnjP0YNnafjLQ",
//		"Key": "id",
//		"Value": "did:example:ebfeb1f712ebc6f1c276e12ec21",
//		"DebugStr": "[\"ZTqbS24eirnjP0YNnafjLQ\",\"id\",\"did:example:ebfeb1f712ebc6f1c276e12ec21\"]",
//		"DebugDigest": "fgoQstuIzTLQ4zqosjUC_qCk-xx3wjDQU2QkQtbn7FI"
//	},
//	{
//		"Result": "WyIyOEEzMmR0OW9JR0lLZW9iVEdIM2F3IiwiZGVncmVlIiwiTUlUIl0",
//		"Salt": "28A32dt9oIGIKeobTGH3aw",
//		"Key": "degree",
//		"Value": "MIT",
//		"DebugStr": "[\"28A32dt9oIGIKeobTGH3aw\",\"degree\",\"MIT\"]",
//		"DebugDigest": "43hfnM7SzZsalAdbXQyq7w4Uvd53YOxTNFpFJr4ZG0A"
//	},
//	{
//		"Result": "WyJUNE8wRlZ2MDBpREhGNFZpYy0wR1VnIiwidHlwZSIsIkJhY2hlbG9yRGVncmVlIl0",
//		"Salt": "T4O0FVv00iDHF4Vic-0GUg",
//		"Key": "type",
//		"Value": "BachelorDegree",
//		"DebugStr": "[\"T4O0FVv00iDHF4Vic-0GUg\",\"type\",\"BachelorDegree\"]",
//		"DebugDigest": "gfseqHmNitIu0-0h14ynqMzuvq1EirTAzUhDnElSVX0"
//	}
//
// ].
func WithRecursiveClaimsObjects(recursiveClaimsObject []string) NewOpt {
	return func(opts *newOpts) {
		opts.recursiveClaimMap = common.SliceToMap(recursiveClaimsObject)
	}
}

// New creates new signed Selective Disclosure JWT based on input claims.
// The Issuer MUST create a Disclosure for each selectively disclosable claim as follows:
// Create an array of three elements in this order:
//
//	A salt value. Generated by the system, the salt value MUST be unique for each claim that is to be selectively
//	disclosed.
//	The claim name, or key, as it would be used in a regular JWT body. This MUST be a string.
//	The claim's value, as it would be used in a regular JWT body. The value MAY be of any type that is allowed in JSON,
//	including numbers, strings, booleans, arrays, and objects.
//
// Then JSON-encode the array such that an UTF-8 string is produced.
// Then base64url-encode the byte representation of the UTF-8 string to create the Disclosure.
func New(issuer string, claims interface{}, headers jose.Headers,
	signer jose.Signer, opts ...NewOpt) (*SelectiveDisclosureJWT, error) {
	nOpts := &newOpts{
		jsonMarshal:    json.Marshal,
		HashAlg:        defaultHash,
		nonSDClaimsMap: make(map[string]bool),
		version:        common.SDJWTVersionDefault,
	}

	for _, opt := range opts {
		opt(nOpts)
	}

	claimsMap, err := afgjwt.PayloadToMap(claims)
	if err != nil {
		return nil, fmt.Errorf("convert payload to map: %w", err)
	}

	// check for the presence of the _sd claim in claims map
	found := common.KeyExistsInMap(common.SDKey, claimsMap)
	if found {
		return nil, fmt.Errorf("key '%s' cannot be present in the claims", common.SDKey)
	}

	sdJWTBuilder := getBuilderByVersion(nOpts.version)
	if nOpts.getSalt == nil {
		nOpts.getSalt = sdJWTBuilder.GenerateSalt
	}

	disclosures, digests, err := sdJWTBuilder.CreateDisclosuresAndDigests("", claimsMap, nOpts)
	if err != nil {
		return nil, err
	}

	payload, err := jsonutil.MergeCustomFields(createPayload(issuer, nOpts), digests)
	if err != nil {
		return nil, fmt.Errorf("failed to merge payload and digests: %w", err)
	}

	signedJWT, err := afgjwt.NewSigned(payload, headers, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create SD-JWT from payload[%+v]: %w", payload, err)
	}

	var disArr []string
	for _, d := range disclosures {
		disArr = append(disArr, d.Result)
	}

	return &SelectiveDisclosureJWT{Disclosures: disArr, SignedJWT: signedJWT}, nil
}

/*
NewFromVC creates new signed Selective Disclosure JWT based on Verifiable Credential in map representation.

Algorithm:
  - extract credential subject map from verifiable credential
  - create un-signed SD-JWT plus Disclosures with credential subject map
  - decode claims from SD-JWT to get credential subject map with selective disclosures
  - replace VC credential subject with newly created credential subject with selective disclosures
  - create signed SD-JWT based on VC
  - return signed SD-JWT plus Disclosures
*/
func NewFromVC(vc map[string]interface{}, headers jose.Headers,
	signer jose.Signer, opts ...NewOpt) (*SelectiveDisclosureJWT, error) {
	nOpts := &newOpts{
		version: common.SDJWTVersionDefault,
	}

	for _, opt := range opts {
		opt(nOpts)
	}

	csObj, ok := common.GetKeyFromVC(credentialSubjectKey, vc)
	if !ok {
		return nil, fmt.Errorf("credential subject not found")
	}

	cs, ok := csObj.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("credential subject must be an object")
	}

	token, err := New("", cs, nil, &unsecuredJWTSigner{}, opts...)
	if err != nil {
		return nil, err
	}

	vcClaims, err := getBuilderByVersion(nOpts.version).ExtractCredentialClaims(vc)
	if err != nil {
		return nil, err
	}

	selectiveCredentialSubject := utils.CopyMap(token.SignedJWT.Payload)
	// move _sd_alg key from credential subject to vc as per example 4 in spec
	vcClaims[common.SDAlgorithmKey] = selectiveCredentialSubject[common.SDAlgorithmKey]
	delete(selectiveCredentialSubject, common.SDAlgorithmKey)

	// move cnf key from credential subject to vc as per example 4 in spec
	cnfObj, ok := selectiveCredentialSubject[common.CNFKey]
	if ok {
		vcClaims[common.CNFKey] = cnfObj

		delete(selectiveCredentialSubject, common.CNFKey)
	}

	// update VC with 'selective' credential subject
	vcClaims[credentialSubjectKey] = selectiveCredentialSubject

	// sign VC with 'selective' credential subject
	signedJWT, err := afgjwt.NewSigned(vc, headers, signer)
	if err != nil {
		return nil, err
	}

	sdJWT := &SelectiveDisclosureJWT{Disclosures: token.Disclosures, SignedJWT: signedJWT}

	return sdJWT, nil
}

func createPayload(issuer string, nOpts *newOpts) *payload {
	var cnf map[string]interface{}
	if nOpts.HolderPublicKey != nil {
		cnf = make(map[string]interface{})
		cnf["jwk"] = nOpts.HolderPublicKey
	}

	payload := &payload{
		Issuer:    issuer,
		JTI:       nOpts.JTI,
		ID:        nOpts.ID,
		Subject:   nOpts.Subject,
		Audience:  nOpts.Audience,
		IssuedAt:  nOpts.IssuedAt,
		Expiry:    nOpts.Expiry,
		NotBefore: nOpts.NotBefore,
		CNF:       cnf,
		SDAlg:     strings.ToLower(nOpts.HashAlg.String()),
	}

	return payload
}

func createDigests(disclosures []*DisclosureEntity, nOpts *newOpts) ([]string, error) {
	var digests []string

	for _, disclosure := range disclosures {
		digest, inErr := createDigest(disclosure, nOpts)
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

func createDigest(disclosure *DisclosureEntity, nOpts *newOpts) (string, error) {
	digest, inErr := common.GetHash(nOpts.HashAlg, disclosure.Result)
	if inErr != nil {
		return "", fmt.Errorf("hash disclosure: %w", inErr)
	}

	disclosure.DebugDigest = digest

	return digest, nil
}

func createDecoyDisclosures(opts *newOpts) ([]*DisclosureEntity, error) {
	if !opts.addDecoyDigests {
		return nil, nil
	}

	n := mr.Intn(decoyMaxElements-decoyMinElements+1) + decoyMinElements

	var decoyDisclosures []*DisclosureEntity

	for i := 0; i < n; i++ {
		salt, err := opts.getSalt()
		if err != nil {
			return nil, err
		}

		decoyDisclosures = append(decoyDisclosures, &DisclosureEntity{
			Salt:   salt,
			Result: salt,
		})
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

func generateSalt(sizeBytes int) (string, error) {
	salt := make([]byte, sizeBytes)

	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	// it is RECOMMENDED to base64url-encode the salt value, producing a string.
	return base64.RawURLEncoding.EncodeToString(salt), nil
}

// payload represents SD-JWT payload.
type payload struct {
	// registered claim names
	Issuer    string           `json:"iss,omitempty"`
	Subject   string           `json:"sub,omitempty"`
	Audience  string           `json:"aud,omitempty"`
	JTI       string           `json:"jti,omitempty"`
	Expiry    *jwt.NumericDate `json:"exp,omitempty"`
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *jwt.NumericDate `json:"iat,omitempty"`

	// non-registered name that can be used for claims based holder binding
	ID string `json:"id,omitempty"`

	// SD-JWT specific
	CNF   map[string]interface{} `json:"cnf,omitempty"`
	SDAlg string                 `json:"_sd_alg,omitempty"`
}

type unsecuredJWTSigner struct{}

func (s unsecuredJWTSigner) Sign(_ []byte) ([]byte, error) {
	return []byte(""), nil
}

func (s unsecuredJWTSigner) Headers() jose.Headers {
	return map[string]interface{}{
		jose.HeaderAlgorithm: afgjwt.AlgorithmNone,
	}
}
