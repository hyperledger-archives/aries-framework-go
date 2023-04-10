/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

// Signer is the signing interface primitive for BBS+ signatures used by Tink.
type Signer interface {
	// Sign will sign create signature of each message and aggregate it into a single signature using the signer's
	// private key.
	// returns:
	// 		signature in []byte
	//		error in case of errors
	Sign(messages [][]byte) ([]byte, error)
}
