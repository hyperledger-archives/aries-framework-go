/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// General serialization/deserialization design based off of https://github.com/square/go-jose/blob/master/jwe.go.

package jose

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
)

// JSONWebEncryption represents a JWE as defined in https://tools.ietf.org/html/rfc7516.
type JSONWebEncryption = jose.JSONWebEncryption

// Recipient is a recipient of a JWE including the shared encryption key.
type Recipient = jose.Recipient

// RecipientHeaders are the recipient headers.
type RecipientHeaders = jose.RecipientHeaders

// Deserialize deserializes the given serialized JWE into a JSONWebEncryption object.
func Deserialize(serializedJWE string) (*JSONWebEncryption, error) {
	return jose.Deserialize(serializedJWE)
}
