/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

// IANA registered JOSE headers (https://tools.ietf.org/html/rfc7515#section-4.1)
const (
	// HeaderAlgorithm identifies the cryptographic algorithm used to secure the JWS.
	HeaderAlgorithm = "alg" // string

	// HeaderJWKSetURL is a URI that refers to a resource for a set of JSON-encoded public keys, one of
	// which corresponds to the key used to digitally sign the JWS.
	HeaderJWKSetURL = "jku" // string

	// HeaderJSONWebKey is the public key that corresponds to the key used to digitally sign the JWS.
	HeaderJSONWebKey = "jwk" // JSON

	// HeaderKeyID is a hint indicating which key was used to secure the JWS.
	HeaderKeyID = "kid" // string

	// HeaderX509URL is a URI that refers to a resource for the X.509 public key certificate or certificate
	// chain corresponding to the key used to digitally sign the JWS.
	HeaderX509URL = "x5u"

	// HeaderX509CertificateChain contains the X.509 public key certificate or certificate chain
	// corresponding to the key used to digitally sign the JWS.
	HeaderX509CertificateChain = "x5c"

	// HeaderX509CertificateDigest (X.509 certificate SHA-1 thumbprint) is a base64url-encoded
	// SHA-1 thumbprint (a.k.a. digest) of the DER encoding of the X.509 certificate corresponding to the key
	// used to digitally sign the JWS.
	HeaderX509CertificateDigestSha1 = "x5t"

	//  HeaderX509CertificateDigestSha256 (X.509 certificate SHA-256 thumbprint) is a base64url-encoded SHA-256
	// thumbprint (a.k.a. digest) of the DER encoding of the X.509 certificate corresponding to the key used to
	// digitally sign the JWS.
	HeaderX509CertificateDigestSha256 = "x5t#S256" // string

	// HeaderType is used by JWS applications to declare the media type of this complete JWS.
	HeaderType = "typ" // string

	// HeaderContentType is used by JWS applications to declare the media type of the
	// secured content (the payload).
	HeaderContentType = "cty" // string

	// HeaderCritical indicates that extensions to this specification and/or are being used that MUST be
	// understood and processed.
	HeaderCritical = "crit" // array
)

// Header defined in https://tools.ietf.org/html/rfc7797
const (
	// HeaderB64 determines whether the payload is represented in the JWS and the JWS Signing
	// Input as ASCII(BASE64URL(JWS Payload)) or as the JWS Payload value itself with no encoding performed.
	HeaderB64Payload = "b64" // bool
)
