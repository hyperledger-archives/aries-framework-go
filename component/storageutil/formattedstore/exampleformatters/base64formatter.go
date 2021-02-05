/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package exampleformatters

import (
	"encoding/base64"

	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

// Base64Formatter is a simple formatter that encodes and decodes base64 data.
type Base64Formatter struct {
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

	return base64.StdEncoding.EncodeToString([]byte(key)), []byte(base64.StdEncoding.EncodeToString(value)),
		formattedTags, nil
}

// Deformat returns base64-decoded versions of formattedKey, formattedValue, and formattedTags.
func (b *Base64Formatter) Deformat(formattedKey string, formattedValue []byte,
	formattedTags ...spi.Tag) (string, []byte, []spi.Tag, error) {
	key, err := base64.StdEncoding.DecodeString(formattedKey)
	if err != nil {
		return "", nil, nil, err
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

	return string(key), value, tags, nil
}
