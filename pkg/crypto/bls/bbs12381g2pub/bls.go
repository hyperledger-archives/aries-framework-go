/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

type BlsG2Pub struct {
}

// Verify makes BLS BBS12-381 signature verification.
func (b BlsG2Pub) Verify(signatures [][]byte, msg, pubKey []byte) error {

	panic("implement me")
}
