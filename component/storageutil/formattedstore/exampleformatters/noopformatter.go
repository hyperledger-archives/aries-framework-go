/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package exampleformatters

import (
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

// NoOpFormatter is a simple "formatter" intended for testing purposes that just passes whatever is passed
// into its methods back out again without modification.
type NoOpFormatter struct{}

// Format takes key, value, and tags and just directly passes them back out without modification.
func (n *NoOpFormatter) Format(key string, value []byte,
	tags ...spi.Tag) (string, []byte, []spi.Tag, error) {
	return key, value, tags, nil
}

// Deformat takes formattedKey, formattedValue, and formattedTags and just directly passes them back out without
// modification.
func (n *NoOpFormatter) Deformat(formattedKey string, formattedValue []byte, formattedTags ...spi.Tag) (string,
	[]byte, []spi.Tag, error) {
	return formattedKey, formattedValue, formattedTags, nil
}

// UsesDeterministicKeyFormatting always returns true since NoOpFormatter always does deterministic key formatting.
func (n *NoOpFormatter) UsesDeterministicKeyFormatting() bool {
	return true
}
