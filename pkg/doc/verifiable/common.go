/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package verifiable provides implementation of Verifiable Credential and Presentation
// (https://www.w3.org/TR/vc-data-model).
// It provides the data structures and functions which allow to process the Verifiable documents on different
// sides and levels. For example, an Issuer can create verifiable.Credential structure and issue it to a
// Holder in JWS. The Holder can decode received Credential and make sure the signature is valid.
// The Holder can present the Credential to the Verifier or combine one or more Credentials into Verifiable
// Presentation. The Verifier can decode received Credentials and Presentations.
//
package verifiable

import (
	"encoding/json"
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

// CustomFields is a map of extra fields of struct build when unmarshalling JSON which are not
// mapped to the struct fields.
type CustomFields map[string]interface{}

// TypedID defines a flexible structure with id and name fields and arbitrary extra fields
// kept in CustomFields.
type TypedID struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`

	CustomFields `json:"-"`
}

// MarshalJSON defines custom marshalling of TypedID to JSON.
func (tid *TypedID) MarshalJSON() ([]byte, error) {
	// TODO hide this exported method
	type Alias TypedID

	alias := (*Alias)(tid)

	data, err := marshalWithCustomFields(alias, tid.CustomFields)
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

	tid.CustomFields = make(CustomFields)

	err := unmarshalWithCustomFields(data, alias, tid.CustomFields)
	if err != nil {
		return fmt.Errorf("unmarshal TypedID: %w", err)
	}

	return nil
}

func newTypedID(v interface{}) (TypedID, error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		return TypedID{}, err
	}

	var tid TypedID
	err = json.Unmarshal(bytes, &tid)

	return tid, err
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

// decodeType decodes raw type(s).
//
// type can be defined as a single string value or array of strings.
func decodeType(t interface{}) ([]string, error) {
	switch rType := t.(type) {
	case string:
		return []string{rType}, nil
	case []interface{}:
		types, err := stringSlice(rType)
		if err != nil {
			return nil, fmt.Errorf("vc types: %w", err)
		}

		return types, nil
	default:
		return nil, errors.New("credential type of unknown structure")
	}
}

// decodeContext decodes raw context(s).
//
// context can be defined as a single string value or array;
// at the second case, the array can be a mix of string and object types
// (objects can express context information); object context are
// defined at the tail of the array.
func decodeContext(c interface{}) ([]string, []interface{}, error) {
	switch rContext := c.(type) {
	case string:
		return []string{rContext}, nil, nil
	case []interface{}:
		strings := make([]string, 0)

		for i := range rContext {
			c, valid := rContext[i].(string)
			if !valid {
				// the remaining contexts are of custom type
				return strings, rContext[i:], nil
			}

			strings = append(strings, c)
		}
		// no contexts of custom type, just string contexts found
		return strings, nil, nil
	default:
		return nil, nil, errors.New("credential context of unknown type")
	}
}
