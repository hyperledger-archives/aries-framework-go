/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package exampleformatters

import (
	"encoding/base64"

	"github.com/google/uuid"

	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

// Base64Formatter is a simple formatter that formats and deformats data between a plaintext format and base64 format.
// It's intended for demonstrating formattedstore functionality. It's not intended for production usage.
type Base64Formatter struct {
	useDeterministicKeyFormatting bool
	keyMap                        map[string]string // Only used if useDeterministicKeyFormatting is true.
}

// NewBase64Formatter creates a new Base64Formatter. If useDeterministicKeyFormatting is set to true, then the
// formatted keys output by the Base64Formatter will simply be base64-encoded versions of the unformatted keys.
// If useDeterministicKeyFormatting is set to false, then the formatted keys will instead be base64-formatted random
// UUIDs, with no relation to the unformatted key. This can be used to simulate the method by which the
// EDV Encrypted Formatter generates its formatted keys by default, which works in a similar way. An in-memory map
// is used to map between the random formatted keys and unformatted keys.
func NewBase64Formatter(useDeterministicKeyFormatting bool) *Base64Formatter {
	return &Base64Formatter{
		useDeterministicKeyFormatting: useDeterministicKeyFormatting,
		keyMap:                        make(map[string]string),
	}
}

// Format returns base64-encoded versions of key, value, and tags.
func (b *Base64Formatter) Format(key string, value []byte, tags ...spi.Tag) (string, []byte, []spi.Tag,
	error) {
	formattedTags := make([]spi.Tag, len(tags))

	for i, tag := range tags {
		formattedTags[i] = spi.Tag{
			Name:  base64.StdEncoding.EncodeToString([]byte(tag.Name)),
			Value: base64.StdEncoding.EncodeToString([]byte(tag.Value)),
		}
	}

	var formattedKey string

	if b.useDeterministicKeyFormatting {
		formattedKey = base64.StdEncoding.EncodeToString([]byte(key))
	} else {
		formattedKey = base64.StdEncoding.EncodeToString([]byte(uuid.New().String()))
		b.keyMap[formattedKey] = key
	}

	return formattedKey, []byte(base64.StdEncoding.EncodeToString(value)),
		formattedTags, nil
}

// Deformat returns base64-decoded versions of formattedKey, formattedValue, and formattedTags.
func (b *Base64Formatter) Deformat(formattedKey string, formattedValue []byte,
	formattedTags ...spi.Tag) (string, []byte, []spi.Tag, error) {
	var key string

	if b.useDeterministicKeyFormatting {
		keyBytes, err := base64.StdEncoding.DecodeString(formattedKey)
		if err != nil {
			return "", nil, nil, err
		}

		key = string(keyBytes)
	} else {
		key = b.keyMap[formattedKey]
	}

	value, err := base64.StdEncoding.DecodeString(string(formattedValue))
	if err != nil {
		return "", nil, nil, err
	}

	tags := make([]spi.Tag, len(formattedTags))

	for i, formattedTag := range formattedTags {
		tagName, err := base64.StdEncoding.DecodeString(formattedTag.Name)
		if err != nil {
			return "", nil, nil, err
		}

		tagValue, err := base64.StdEncoding.DecodeString(formattedTag.Value)
		if err != nil {
			return "", nil, nil, err
		}

		tags[i] = spi.Tag{
			Name:  string(tagName),
			Value: string(tagValue),
		}
	}

	return key, value, tags, nil
}

// UsesDeterministicKeyFormatting indicates whether this Base64Formatter has been set up to use deterministic key
// generation.
func (b *Base64Formatter) UsesDeterministicKeyFormatting() bool {
	return b.useDeterministicKeyFormatting
}
