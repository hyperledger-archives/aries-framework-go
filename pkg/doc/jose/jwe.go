/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

// JSONWebEncryption represents a JWE as defined in https://tools.ietf.org/html/rfc7516.
type JSONWebEncryption struct {
	ProtectedHeaders   Headers
	UnprotectedHeaders Headers
	Recipients         []Recipient
	AAD                string
	IV                 string
	Ciphertext         string
	Tag                string
}

// Recipient is a recipient of a JWE including the shared encryption key
type Recipient struct {
	EncryptedKey string           `json:"encrypted_key,omitempty"`
	Header       RecipientHeaders `json:"header,omitempty"`
}

// RecipientHeaders are the recipient headers
type RecipientHeaders struct {
	APU string `json:"apu,omitempty"`
	IV  string `json:"iv,omitempty"`
	Tag string `json:"tag,omitempty"`
	KID string `json:"kid,omitempty"`
	SPK string `json:"spk,omitempty"`
}

// rawJSONWebEncryption represents a RAW JWE that is used for serialization/deserialization.
type rawJSONWebEncryption struct {
	ProtectedHeaders   string          `json:"protected,omitempty"`
	UnprotectedHeaders json.RawMessage `json:"unprotected,omitempty"`
	Recipients         json.RawMessage `json:"recipients,omitempty"`
	AAD                string          `json:"aad,omitempty"`
	IV                 string          `json:"iv,omitempty"`
	Ciphertext         string          `json:"ciphertext,omitempty"`
	Tag                string          `json:"tag,omitempty"`
}

var errEmptyCiphertext = errors.New("ciphertext cannot be empty")

type marshalFunc func(interface{}) ([]byte, error)

// Serialize serializes the given JWE into JSON as defined in https://tools.ietf.org/html/rfc7516#section-7.2.
func (e *JSONWebEncryption) Serialize(marshal marshalFunc) (string, error) {
	b64ProtectedHeaders, unprotectedHeaders, err := e.prepareHeaders(marshal)
	if err != nil {
		return "", err
	}

	var recipientsJSON json.RawMessage
	if e.Recipients == nil {
		// The spec requires that the "recipients" must always be an array and be present,
		// even if some or all of the array values are the empty JSON object "{}".
		recipientsJSON = json.RawMessage("[{}]")
	} else {
		nonEmptyRecipientsJSON, errMarshal := marshal(e.Recipients)
		if errMarshal != nil {
			return "", errMarshal
		}

		recipientsJSON = nonEmptyRecipientsJSON
	}

	b64AAD := base64.RawURLEncoding.EncodeToString([]byte(e.AAD))

	b64IV := base64.RawURLEncoding.EncodeToString([]byte(e.IV))

	if e.Ciphertext == "" {
		return "", errEmptyCiphertext
	}

	b64Ciphertext := base64.RawURLEncoding.EncodeToString([]byte(e.Ciphertext))

	b64Tag := base64.RawURLEncoding.EncodeToString([]byte(e.Tag))

	preparedJWE := rawJSONWebEncryption{
		ProtectedHeaders:   b64ProtectedHeaders,
		UnprotectedHeaders: unprotectedHeaders,
		Recipients:         recipientsJSON,
		AAD:                b64AAD,
		IV:                 b64IV,
		Ciphertext:         b64Ciphertext,
		Tag:                b64Tag,
	}

	serializedJWE, err := marshal(preparedJWE)
	if err != nil {
		return "", err
	}

	return string(serializedJWE), nil
}

func (e *JSONWebEncryption) prepareHeaders(marshal marshalFunc) (string, json.RawMessage, error) {
	var b64ProtectedHeaders string

	if e.ProtectedHeaders != nil {
		protectedHeadersJSON, err := marshal(e.ProtectedHeaders)
		if err != nil {
			return "", nil, err
		}

		b64ProtectedHeaders = base64.RawURLEncoding.EncodeToString(protectedHeadersJSON)
	}

	var unprotectedHeaders json.RawMessage

	if e.UnprotectedHeaders != nil {
		unprotectedHeadersJSON, err := marshal(e.UnprotectedHeaders)
		if err != nil {
			return "", nil, err
		}

		unprotectedHeaders = unprotectedHeadersJSON
	}

	return b64ProtectedHeaders, unprotectedHeaders, nil
}
