/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didkeyutil

import (
	"strings"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

// ConvertBase58KeysToDIDKeys converts base58 keys array to did:key keys array.
func ConvertBase58KeysToDIDKeys(keys []string) []string {
	var didKeys []string

	for _, key := range keys {
		if key == "" {
			didKeys = append(didKeys, key)
			continue
		}

		// skip if the key is a relative did-url (ie, it starts with ?, /, or #)
		if strings.Contains("?/#", string(key[0])) { // nolint:gocritic
			didKeys = append(didKeys, key)
			continue
		}

		// skip if the key is already a did
		if strings.HasPrefix(key, "did:") {
			didKeys = append(didKeys, key)
			continue
		}

		rawKey := base58.Decode(key)
		if len(rawKey) == 0 {
			didKeys = append(didKeys, key)
			continue
		}

		didKey, _ := fingerprint.CreateDIDKey(rawKey)

		didKeys = append(didKeys, didKey)
	}

	return didKeys
}

// ConvertDIDKeysToBase58Keys converts base58 keys array to did:key keys array.
func ConvertDIDKeysToBase58Keys(keys []string) []string {
	var base58Keys []string

	for _, key := range keys {
		if strings.HasPrefix(key, "did:key:") {
			rawKey, _ := fingerprint.PubKeyFromDIDKey(key) //nolint: errcheck

			base58Keys = append(base58Keys, base58.Encode(rawKey))
		} else {
			base58Keys = append(base58Keys, key)
		}
	}

	return base58Keys
}
