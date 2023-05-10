/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// General serialization/deserialization design based off of https://github.com/square/go-jose/blob/master/jwe.go.

package jose

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	compactJWERequiredNumOfParts      = 5
	errCompactSerializationCommonText = "unable to compact serialize: "
)

var (
	errWrongNumberOfCompactJWEParts = errors.New("invalid compact JWE: it must have five parts")
	errEmptyCiphertext              = errors.New("ciphertext cannot be empty")
	errProtectedHeaderMissing       = errors.New(errCompactSerializationCommonText +
		"no protected header found")
)

var errNotOnlyOneRecipient = errors.New(errCompactSerializationCommonText +
	"JWE compact serialization only supports JWE with exactly one single recipient")

var errUnprotectedHeaderUnsupported = errors.New(errCompactSerializationCommonText +
	"JWE compact serialization does not support a shared unprotected header")

var errAADHeaderUnsupported = errors.New(errCompactSerializationCommonText +
	"JWE compact serialization does not support AAD")

var errPerRecipientHeaderUnsupported = errors.New(errCompactSerializationCommonText +
	"JWE compact serialization does not support a per-recipient unprotected header")

// JSONWebEncryption represents a JWE as defined in https://tools.ietf.org/html/rfc7516.
type JSONWebEncryption struct {
	ProtectedHeaders   Headers
	OrigProtectedHders string
	UnprotectedHeaders Headers
	Recipients         []*Recipient
	AAD                string
	IV                 string
	Ciphertext         string
	Tag                string
}

// Recipient is a recipient of a JWE including the shared encryption key.
type Recipient struct {
	Header       *RecipientHeaders `json:"header,omitempty"`
	EncryptedKey string            `json:"encrypted_key,omitempty"`
}

// RecipientHeaders are the recipient headers.
type RecipientHeaders struct {
	Alg string          `json:"alg,omitempty"`
	APU string          `json:"apu,omitempty"`
	APV string          `json:"apv,omitempty"`
	IV  string          `json:"iv,omitempty"`
	Tag string          `json:"tag,omitempty"`
	KID string          `json:"kid,omitempty"`
	EPK json.RawMessage `json:"epk,omitempty"`
}

// rawJSONWebEncryption represents a RAW JWE that is used for serialization/deserialization.
type rawJSONWebEncryption struct {
	B64ProtectedHeaders      string          `json:"protected,omitempty"`
	UnprotectedHeaders       json.RawMessage `json:"unprotected,omitempty"`
	Recipients               json.RawMessage `json:"recipients,omitempty"`
	B64SingleRecipientEncKey string          `json:"encrypted_key,omitempty"`
	SingleRecipientHeader    json.RawMessage `json:"header,omitempty"`
	B64AAD                   string          `json:"aad,omitempty"`
	B64IV                    string          `json:"iv,omitempty"`
	B64Ciphertext            string          `json:"ciphertext,omitempty"`
	B64Tag                   string          `json:"tag,omitempty"`
}

type marshalFunc func(interface{}) ([]byte, error)

// FullSerialize serializes the given JWE into JSON as defined in https://tools.ietf.org/html/rfc7516#section-7.2.
// The full serialization syntax is used. If there is only one recipient, then the flattened syntax is used.
func (e *JSONWebEncryption) FullSerialize(marshal marshalFunc) (string, error) {
	b64ProtectedHeaders, unprotectedHeaders, err := e.prepareHeaders(marshal)
	if err != nil {
		return "", err
	}

	recipientsJSON, b64SingleRecipientEncKey, singleRecipientHeader, err := e.prepareRecipients(marshal)
	if err != nil {
		return "", err
	}

	b64AAD := base64.RawURLEncoding.EncodeToString([]byte(e.AAD))

	b64IV := base64.RawURLEncoding.EncodeToString([]byte(e.IV))

	if e.Ciphertext == "" {
		return "", errEmptyCiphertext
	}

	b64Ciphertext := base64.RawURLEncoding.EncodeToString([]byte(e.Ciphertext))

	b64Tag := base64.RawURLEncoding.EncodeToString([]byte(e.Tag))

	preparedJWE := rawJSONWebEncryption{
		B64ProtectedHeaders:      b64ProtectedHeaders,
		UnprotectedHeaders:       unprotectedHeaders,
		Recipients:               recipientsJSON,
		B64SingleRecipientEncKey: b64SingleRecipientEncKey,
		SingleRecipientHeader:    singleRecipientHeader,
		B64AAD:                   b64AAD,
		B64IV:                    b64IV,
		B64Ciphertext:            b64Ciphertext,
		B64Tag:                   b64Tag,
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

func (e *JSONWebEncryption) prepareRecipients(marshal marshalFunc) (json.RawMessage, string, []byte, error) {
	var recipientsJSON json.RawMessage

	var b64SingleRecipientEncKey string

	var singleRecipientHeader []byte

	switch len(e.Recipients) {
	case 0:
		// The spec requires that the "recipients" field must always be an array and be present,
		// even if some or all of the array values are the empty JSON object "{}".
		recipientsJSON = json.RawMessage("[{}]")
	case 1:
		// Use flattened JWE JSON serialization syntax as defined in https://tools.ietf.org/html/rfc7516#section-7.2.2.
		b64SingleRecipientEncKey = base64.RawURLEncoding.EncodeToString([]byte(e.Recipients[0].EncryptedKey))

		if e.Recipients[0].Header != nil {
			var errMarshal error

			singleRecipientHeader, errMarshal = marshal(e.Recipients[0].Header)
			if errMarshal != nil {
				return nil, "", nil, errMarshal
			}
		}
	default:
		// Make copy of Recipients array so we don't change the underlying object
		recipientsToMarshal := make([]Recipient, len(e.Recipients))
		for i, recipient := range e.Recipients {
			recipientsToMarshal[i].EncryptedKey = base64.RawURLEncoding.EncodeToString([]byte(recipient.EncryptedKey))
			recipientsToMarshal[i].Header = recipient.Header
		}

		nonEmptyRecipientsJSON, errMarshal := marshal(recipientsToMarshal)
		if errMarshal != nil {
			return nil, "", nil, errMarshal
		}

		recipientsJSON = nonEmptyRecipientsJSON
	}

	return recipientsJSON, b64SingleRecipientEncKey, singleRecipientHeader, nil
}

// CompactSerialize serializes the given JWE into a compact, URL-safe string as defined in
// https://tools.ietf.org/html/rfc7516#section-7.1.
func (e *JSONWebEncryption) CompactSerialize(marshal marshalFunc) (string, error) {
	if e.ProtectedHeaders == nil {
		return "", errProtectedHeaderMissing
	}

	if len(e.Recipients) != 1 {
		return "", errNotOnlyOneRecipient
	}

	if e.UnprotectedHeaders != nil {
		return "", errUnprotectedHeaderUnsupported
	}

	if e.AAD != "" {
		return "", errAADHeaderUnsupported
	}

	if e.Recipients[0].Header != nil {
		return "", errPerRecipientHeaderUnsupported
	}

	protectedHeadersJSON, err := marshal(e.ProtectedHeaders)
	if err != nil {
		return "", err
	}

	b64ProtectedHeader := base64.RawURLEncoding.EncodeToString(protectedHeadersJSON)

	b64EncryptedKey := base64.RawURLEncoding.EncodeToString([]byte(e.Recipients[0].EncryptedKey))

	b64IV := base64.RawURLEncoding.EncodeToString([]byte(e.IV))

	b64Ciphertext := base64.RawURLEncoding.EncodeToString([]byte(e.Ciphertext))

	b64Tag := base64.RawURLEncoding.EncodeToString([]byte(e.Tag))

	return fmt.Sprintf("%s.%s.%s.%s.%s", b64ProtectedHeader, b64EncryptedKey, b64IV, b64Ciphertext, b64Tag), nil
}

// Deserialize deserializes the given serialized JWE into a JSONWebEncryption object.
func Deserialize(serializedJWE string) (*JSONWebEncryption, error) {
	if strings.HasPrefix(serializedJWE, "{") {
		return deserializeFull(serializedJWE)
	}

	return deserializeCompact(serializedJWE)
}

func deserializeFull(serializedJWE string) (*JSONWebEncryption, error) {
	rawJWE := rawJSONWebEncryption{}

	err := json.Unmarshal([]byte(serializedJWE), &rawJWE)
	if err != nil {
		return nil, err
	}

	return deserializeFromRawJWE(&rawJWE)
}

func deserializeCompact(serializedJWE string) (*JSONWebEncryption, error) {
	parts := strings.Split(serializedJWE, ".")
	if len(parts) != compactJWERequiredNumOfParts {
		return nil, errWrongNumberOfCompactJWEParts
	}

	rawJWE := rawJSONWebEncryption{
		B64ProtectedHeaders:      parts[0],
		B64SingleRecipientEncKey: parts[1],
		B64IV:                    parts[2],
		B64Ciphertext:            parts[3],
		B64Tag:                   parts[4],
	}

	return deserializeFromRawJWE(&rawJWE)
}

func deserializeFromRawJWE(rawJWE *rawJSONWebEncryption) (*JSONWebEncryption, error) {
	protectedHeaders, unprotectedHeaders, err := deserializeAndDecodeHeaders(rawJWE)
	if err != nil {
		return nil, err
	}

	recipients, err := deserializeRecipients(rawJWE)
	if err != nil {
		return nil, err
	}

	aad, err := base64.RawURLEncoding.DecodeString(rawJWE.B64AAD)
	if err != nil {
		return nil, err
	}

	iv, err := base64.RawURLEncoding.DecodeString(rawJWE.B64IV)
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(rawJWE.B64Ciphertext)
	if err != nil {
		return nil, err
	}

	tag, err := base64.RawURLEncoding.DecodeString(rawJWE.B64Tag)
	if err != nil {
		return nil, err
	}

	deserializedJWE := JSONWebEncryption{
		ProtectedHeaders:   *protectedHeaders,
		OrigProtectedHders: rawJWE.B64ProtectedHeaders,
		UnprotectedHeaders: *unprotectedHeaders,
		Recipients:         recipients,
		AAD:                string(aad),
		IV:                 string(iv),
		Ciphertext:         string(ciphertext),
		Tag:                string(tag),
	}

	return &deserializedJWE, nil
}

func deserializeAndDecodeHeaders(rawJWE *rawJSONWebEncryption) (*Headers, *Headers, error) {
	protectedHeadersBytes, err := base64.RawURLEncoding.DecodeString(rawJWE.B64ProtectedHeaders)
	if err != nil {
		return nil, nil, err
	}

	var protectedHeaders Headers

	err = json.Unmarshal(protectedHeadersBytes, &protectedHeaders)
	if err != nil {
		return nil, nil, err
	}

	var unprotectedHeaders Headers

	if rawJWE.UnprotectedHeaders != nil {
		err = json.Unmarshal(rawJWE.UnprotectedHeaders, &unprotectedHeaders)
		if err != nil {
			return nil, nil, err
		}
	}

	return &protectedHeaders, &unprotectedHeaders, nil
}

func parseDeserializeRecipients(rawJWE *rawJSONWebEncryption) ([]*Recipient, error) {
	if rawJWE.Recipients != nil {
		var recipients []*Recipient

		err := json.Unmarshal(rawJWE.Recipients, &recipients)
		if err != nil {
			return nil, err
		}

		return recipients, nil
	}

	// If there is no recipients field, then we must be deserializing JWE with the flattened syntax as defined in
	// https://tools.ietf.org/html/rfc7516#section-7.2.2.
	recipient := &Recipient{EncryptedKey: rawJWE.B64SingleRecipientEncKey}

	if rawJWE.SingleRecipientHeader != nil {
		err := json.Unmarshal(rawJWE.SingleRecipientHeader, &recipient.Header)
		if err != nil {
			return nil, err
		}
	}

	return []*Recipient{recipient}, nil
}

func deserializeRecipients(rawJWE *rawJSONWebEncryption) ([]*Recipient, error) {
	recipients, err := parseDeserializeRecipients(rawJWE)
	if err != nil {
		return nil, err
	}

	for _, recipient := range recipients {
		decodedEncKey, err := base64.RawURLEncoding.DecodeString(recipient.EncryptedKey)
		if err != nil {
			return nil, err
		}

		recipient.EncryptedKey = string(decodedEncKey)
	}

	return recipients, nil
}
