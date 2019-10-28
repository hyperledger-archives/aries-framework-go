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

// jwtDecoding defines if to decode VC from JWT
type jwtDecoding int

const (
	// noJwtDecoding not a JWT
	noJwtDecoding jwtDecoding = iota

	// jwsDecoding indicated to unmarshal from Signed Token
	jwsDecoding

	// unsecuredJWTDecoding indicates to unmarshal from Unsecured Token
	unsecuredJWTDecoding
)

// JWSAlgorithm defines JWT signature algorithms of Verifiable Credential
type JWSAlgorithm int

const (
	// RS256 JWT Algorithm
	RS256 JWSAlgorithm = iota

	// EdDSA JWT Algorithm
	EdDSA

	// TODO support ES256K (https://github.com/square/go-jose/issues/263)
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
// TODO hide this exported method
func (tid *TypedID) MarshalJSON() ([]byte, error) {
	type Alias TypedID
	alias := (*Alias)(tid)

	data, err := marshalWithExtraFields(alias, tid.ExtraFields)
	if err != nil {
		return nil, fmt.Errorf("marshal TypedID: %w", err)
	}

	return data, nil
}

// UnmarshalJSON defines custom unmarshalling of TypedID from JSON.
// TODO hide this exported method
func (tid *TypedID) UnmarshalJSON(data []byte) error {
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
