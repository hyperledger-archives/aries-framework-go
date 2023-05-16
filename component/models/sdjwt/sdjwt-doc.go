/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package sdjwt implements creating JSON Web Token (JWT) documents that support selective disclosure of JWT claims.
//
// In an SD-JWT, claims can be hidden, but cryptographically protected against undetected modification.
//
// When issuing the SD-JWT to the Holder, the Issuer also sends the cleartext counterparts of all hidden claims,
// the so-called Disclosures, separate from the SD-JWT itself.
//
// The Holder decides which claims to disclose to a Verifier and forwards the respective Disclosures
// together with the SD-JWT to the Verifier.
//
// The Verifier has to verify that all disclosed claim values were part of the original, Issuer-signed SD-JWT.
// The Verifier will not, however, learn any claim values not disclosed in the Disclosures.
//
// This implementation supports:
//
// - selectively disclosable claims in flat data structures as well as more complex, nested data structures
//
// - combining selectively disclosable claims with clear-text claims that are always disclosed
//
// - options for specifying registered claim names that will be included in plaintext (e.g. iss, exp, or nbf)
//
// - option for configuring clear-text claims
//
// For selectively disclosable claims, claim names are always blinded.
//
// This implementation also supports an optional mechanism for Holder Binding,
// the concept of binding an SD-JWT to key material controlled by the Holder.
// The strength of the Holder Binding is conditional upon the trust in the protection
// of the private key of the key pair an SD-JWT is bound to.
package sdjwt
