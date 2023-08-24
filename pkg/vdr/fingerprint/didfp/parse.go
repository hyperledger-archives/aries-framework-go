/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didfp

import (
	"github.com/trustbloc/kms-go/doc/util/fingerprint"
)

// MethodIDFromDIDKey parses the did:key DID and returns it's specific Method ID.
func MethodIDFromDIDKey(didKey string) (string, error) {
	return fingerprint.MethodIDFromDIDKey(didKey)
}
