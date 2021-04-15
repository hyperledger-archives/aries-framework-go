/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

// IANA registered JOSE headers (https://tools.ietf.org/html/rfc7515#section-4.1)
const (
	// HeaderAlgorithm identifies:
	// For JWS: the cryptographic algorithm used to secure the JWS.
	// For JWE: the cryptographic algorithm used to encrypt or determine the value of the CEK.
	HeaderAlgorithm = "alg" // string

	// HeaderEncryption identifies the JWE content encryption algorithm.
	HeaderEncryption = "enc" // string

	// HeaderJWKSetURL is a URI that refers to a resource for a set of JSON-encoded public keys, one of which:
	// For JWS: corresponds to the key used to digitally sign the JWS.
	// For JWE: corresponds to the public key to which the JWE was encrypted.
	HeaderJWKSetURL = "jku" // string

	// HeaderJSONWebKey is:
	// For JWS: the public key that corresponds to the key used to digitally sign the JWS.
	// For JWE: the public key to which the JWE was encrypted.
	HeaderJSONWebKey = "jwk" // JSON

	// HeaderKeyID is a hint:
	// For JWS: indicating which key was used to secure the JWS.
	// For JWE: which references the public key to which the JWE was encrypted.
	HeaderKeyID = "kid" // string

	// HeaderSenderKeyID is a hint:
	// For JWS: not used.
	// For JWE: which references the (sender) public key used in the JWE key derivation/wrapping to encrypt the CEK.
	HeaderSenderKeyID = "skid" // string

	// HeaderX509URL is a URI that refers to a resource for the X.509 public key certificate or certificate chain:
	// For JWS: corresponding to the key used to digitally sign the JWS.
	// For JWE: corresponding to the public key to which the JWE was encrypted.
	HeaderX509URL = "x5u"

	// HeaderX509CertificateChain contains the X.509 public key certificate or certificate chain:
	// For JWS: corresponding to the key used to digitally sign the JWS.
	// For JWE: corresponding to the public key to which the JWE was encrypted.
	HeaderX509CertificateChain = "x5c"

	// HeaderX509CertificateDigest (X.509 certificate SHA-1 thumbprint) is a base64url-encoded
	// SHA-1 thumbprint (a.k.a. digest) of the DER encoding of the X.509 certificate:
	// For JWS: corresponding to the key used to digitally sign the JWS.
	// For JWE: corresponding to the public key to which the JWE was encrypted.
	HeaderX509CertificateDigestSha1 = "x5t"

	// HeaderX509CertificateDigestSha256 (X.509 certificate SHA-256 thumbprint) is a base64url-encoded SHA-256
	// thumbprint (a.k.a. digest) of the DER encoding of the X.509 certificate:
	// For JWS: corresponding to the key used to digitally sign the JWS.
	// For JWE: corresponding to the public key to which the JWE was encrypted.
	HeaderX509CertificateDigestSha256 = "x5t#S256" // string

	// HeaderType is:
	// For JWS: used by JWS applications to declare the media type of this complete JWS.
	// For JWE: used by JWE applications to declare the media type of this complete JWE.
	HeaderType = "typ" // string

	// HeaderContentType is used by JWS applications to declare the media type of:
	// For JWS: the secured content (the payload).
	// For JWE: the secured content (the plaintext).
	HeaderContentType = "cty" // string

	// HeaderCritical indicates that extensions to:
	// For JWS: this JWS header specification and/or JWA are being used that MUST be understood and processed.
	// For JWE: this JWE header specification and/or JWA are being used that MUST be understood and processed.
	HeaderCritical = "crit" // array

	// HeaderEPK is used by JWE applications to wrap/unwrap the CEK for a recipient.
	HeaderEPK = "epk" // JSON
)

// Header defined in https://tools.ietf.org/html/rfc7797
const (
	// HeaderB64 determines whether the payload is represented in the JWS and the JWS Signing
	// Input as ASCII(BASE64URL(JWS Payload)) or as the JWS Payload value itself with no encoding performed.
	HeaderB64Payload = "b64" // bool
	// A256GCMALG is the default content encryption algorithm value as per
	// the JWA specification: https://tools.ietf.org/html/rfc7518#section-5.1
	A256GCMALG = "A256GCM"
	// XC20PALG represented XChacha20Poly1305 content encryption algorithm value.
	XC20PALG = "XC20P"
)

// Headers represents JOSE headers.
type Headers map[string]interface{}

// KeyID gets Key ID from JOSE headers.
func (h Headers) KeyID() (string, bool) {
	return h.stringValue(HeaderKeyID)
}

// SenderKeyID gets the sender Key ID from Jose headers.
func (h Headers) SenderKeyID() (string, bool) {
	return h.stringValue(HeaderSenderKeyID)
}

// Algorithm gets Algorithm from JOSE headers.
func (h Headers) Algorithm() (string, bool) {
	return h.stringValue(HeaderAlgorithm)
}

// Encryption gets content encryption algorithm from JOSE headers.
func (h Headers) Encryption() (string, bool) {
	return h.stringValue(HeaderEncryption)
}

// Type gets content encryption type from JOSE headers.
func (h Headers) Type() (string, bool) {
	return h.stringValue(HeaderType)
}

// ContentType gets the payload content type from JOSE headers.
func (h Headers) ContentType() (string, bool) {
	return h.stringValue(HeaderContentType)
}

func (h Headers) stringValue(key string) (string, bool) {
	raw, ok := h[key]
	if !ok {
		return "", false
	}

	str, ok := raw.(string)

	return str, ok
}
