/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didfp

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
)

// MethodIDFromDIDKey parses the did:key DID and returns it's specific Method ID.
func MethodIDFromDIDKey(didKey string) (string, error) {
	return fingerprint.MethodIDFromDIDKey(didKey)
}
