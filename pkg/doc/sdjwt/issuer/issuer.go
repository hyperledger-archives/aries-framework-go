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

	"github.com/go-jose/go-jose/v3/jwt"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/issuer"
)

// Claims defines JSON Web Token Claims (https://tools.ietf.org/html/rfc7519#section-4)
type Claims = issuer.Claims

// NewOpt is the SD-JWT New option.
type NewOpt = issuer.NewOpt

// WithJSONMarshaller is option is for marshalling disclosure.
func WithJSONMarshaller(jsonMarshal func(v interface{}) ([]byte, error)) NewOpt {
	return issuer.WithJSONMarshaller(jsonMarshal)
}

// WithSaltFnc is an option for generating salt. Mostly used for testing.
// A new salt MUST be chosen for each claim independently of other salts.
// The RECOMMENDED minimum length of the randomly-generated portion of the salt is 128 bits.
// It is RECOMMENDED to base64url-encode the salt value, producing a string.
func WithSaltFnc(fnc func() (string, error)) NewOpt {
	return issuer.WithSaltFnc(fnc)
}

// WithIssuedAt is an option for SD-JWT payload. This is a clear-text claim that is always disclosed.
func WithIssuedAt(issuedAt *jwt.NumericDate) NewOpt {
	return issuer.WithIssuedAt(issuedAt)
}

// WithAudience is an option for SD-JWT payload. This is a clear-text claim that is always disclosed.
func WithAudience(audience string) NewOpt {
	return issuer.WithAudience(audience)
}

// WithExpiry is an option for SD-JWT payload. This is a clear-text claim that is always disclosed.
func WithExpiry(expiry *jwt.NumericDate) NewOpt {
	return issuer.WithExpiry(expiry)
}

// WithNotBefore is an option for SD-JWT payload. This is a clear-text claim that is always disclosed.
func WithNotBefore(notBefore *jwt.NumericDate) NewOpt {
	return issuer.WithNotBefore(notBefore)
}

// WithSubject is an option for SD-JWT payload. This is a clear-text claim that is always disclosed.
func WithSubject(subject string) NewOpt {
	return issuer.WithSubject(subject)
}

// WithJTI is an option for SD-JWT payload. This is a clear-text claim that is always disclosed.
func WithJTI(jti string) NewOpt {
	return issuer.WithJTI(jti)
}

// WithID is an option for SD-JWT payload. This is a clear-text claim that is always disclosed.
func WithID(id string) NewOpt {
	return issuer.WithID(id)
}

// WithHolderPublicKey is an option for SD-JWT payload.
// The Holder can prove legitimate possession of an SD-JWT by proving control over the same private key during
// the issuance and presentation. An SD-JWT with Holder Binding contains a public key or a reference to a public key
// that matches to the private key controlled by the Holder.
// The "cnf" claim value MUST represent only a single proof-of-possession key. This implementation is using CNF "jwk".
func WithHolderPublicKey(jwk *jwk.JWK) NewOpt {
	return issuer.WithHolderPublicKey(jwk)
}

// WithHashAlgorithm is an option for hashing disclosures.
func WithHashAlgorithm(alg crypto.Hash) NewOpt {
	return issuer.WithHashAlgorithm(alg)
}

// WithDecoyDigests is an option for adding decoy digests(default is false).
func WithDecoyDigests(flag bool) NewOpt {
	return issuer.WithDecoyDigests(flag)
}

// WithStructuredClaims is an option for handling structured claims(default is false).
func WithStructuredClaims(flag bool) NewOpt {
	return issuer.WithStructuredClaims(flag)
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
	return issuer.WithNonSelectivelyDisclosableClaims(nonSDClaims)
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
func New(iss string, claims interface{}, headers jose.Headers,
	signer jose.Signer, opts ...NewOpt) (*SelectiveDisclosureJWT, error) {
	return issuer.New(iss, claims, headers, signer, opts...)
}

/*
NewFromVC creates new signed Selective Disclosure JWT based on Verifiable Credential.

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
	return issuer.NewFromVC(vc, headers, signer, opts...)
}

// SelectiveDisclosureJWT defines Selective Disclosure JSON Web Token (https://tools.ietf.org/html/rfc7519)
type SelectiveDisclosureJWT = issuer.SelectiveDisclosureJWT
