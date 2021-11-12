/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didfp

import (
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// MethodIDFromDIDKey parses the did:key DID and returns it's specific Method ID.
func MethodIDFromDIDKey(didKey string) (string, error) {
	id, err := did.Parse(didKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse did:key [%s]: %w", didKey, err)
	}

	// did:key is hard-coded to base58btc:
	// - https://w3c-ccg.github.io/did-method-key/
	// - https://github.com/multiformats/multibase#multibase-table
	if !strings.HasPrefix(id.MethodSpecificID, "z") {
		return "", fmt.Errorf("not a valid did:key identifier (not a base58btc multicodec): %s", didKey)
	}

	return id.MethodSpecificID, nil
}
