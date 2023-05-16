/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package fingerprint

import (
	"fmt"
	"strings"
)

// MethodIDFromDIDKey parses the did:key DID and returns it's specific Method ID.
func MethodIDFromDIDKey(didKey string) (string, error) {
	msID, err := getMethodSpecificID(didKey)
	if err != nil {
		return "", err
	}

	// did:key is hard-coded to base58btc:
	// - https://w3c-ccg.github.io/did-method-key/
	// - https://github.com/multiformats/multibase#multibase-table
	if !strings.HasPrefix(msID, "z") {
		return "", fmt.Errorf("not a valid did:key identifier (not a base58btc multicodec): %s", didKey)
	}

	return msID, nil
}

func getMethodSpecificID(did string) (string, error) {
	parts := strings.SplitN(did, ":", 3)

	if len(parts) < 3 {
		return "", fmt.Errorf("invalid did")
	}

	return parts[2], nil
}
