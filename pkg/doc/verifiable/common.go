/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"errors"
	"fmt"

	"github.com/square/go-jose/v3"
	"github.com/xeipuuv/gojsonschema"
)

// TODO https://github.com/square/go-jose/issues/263 support ES256K

// JWSAlgorithm defines JWT signature algorithms of Verifiable Credential
type JWSAlgorithm int

const (
	// RS256 JWT Algorithm
	RS256 JWSAlgorithm = iota

	// EdDSA JWT Algorithm
	EdDSA
)

// jose converts JWSAlgorithm to JOSE one.
func (ja JWSAlgorithm) jose() (jose.SignatureAlgorithm, error) {
	switch ja {
	case RS256:
		return jose.RS256, nil
	case EdDSA:
		return jose.EdDSA, nil
	default:
		return "", fmt.Errorf("unsupported algorithm: %v", ja)
	}
}

// PublicKeyFetcher fetches public key for JWT signing verification based on Issuer ID (possibly DID)
// and Key ID.
// If not defined, JWT encoding is not tested.
type PublicKeyFetcher func(issuerID, keyID string) (interface{}, error)

// SingleKey defines the case when only one verification key is used and we don't need to pick the one.
func SingleKey(pubKey interface{}) PublicKeyFetcher {
	return func(issuerID, keyID string) (interface{}, error) {
		return pubKey, nil
	}
}

// Proof defines embedded proof of Verifiable Credential
type Proof interface{}

// ExtraFields is a map of extra fields of struct build when unmarshalling JSON which are not
// mapped to the struct fields.
type ExtraFields map[string]interface{}

// TypedID defines a flexible structure with id and name fields and arbitrary extra fields
// kept in ExtraFields.
type TypedID struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`

	ExtraFields `json:"-"`
}

// MarshalJSON defines custom marshalling of TypedID to JSON.
func (tid *TypedID) MarshalJSON() ([]byte, error) {
	// TODO hide this exported method
	type Alias TypedID

	alias := (*Alias)(tid)

	data, err := marshalWithExtraFields(alias, tid.ExtraFields)
	if err != nil {
		return nil, fmt.Errorf("marshal TypedID: %w", err)
	}

	return data, nil
}

// UnmarshalJSON defines custom unmarshalling of TypedID from JSON.
func (tid *TypedID) UnmarshalJSON(data []byte) error {
	// TODO hide this exported method
	type Alias TypedID

	alias := (*Alias)(tid)

	tid.ExtraFields = make(ExtraFields)

	err := unmarshalWithExtraFields(data, alias, tid.ExtraFields)
	if err != nil {
		return fmt.Errorf("unmarshal TypedID: %w", err)
	}

	return nil
}

func describeSchemaValidationError(result *gojsonschema.Result, what string) string {
	errMsg := what + " is not valid:\n"
	for _, desc := range result.Errors() {
		errMsg += fmt.Sprintf("- %s\n", desc)
	}

	return errMsg
}

func stringSlice(values []interface{}) ([]string, error) {
	strings := make([]string, len(values))

	for i := range values {
		t, valid := values[i].(string)
		if !valid {
			return nil, errors.New("array element is not a string")
		}

		strings[i] = t
	}

	return strings, nil
}
