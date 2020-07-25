/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptoutil

import "golang.org/x/crypto/blake2b"

// Nonce makes a nonce using blake2b, to match the format expected by libsodium.
func Nonce(pub1, pub2 []byte) (*[NonceSize]byte, error) {
	var nonce [NonceSize]byte
	// generate an equivalent nonce to libsodium's (see link above)
	nonceWriter, err := blake2b.New(NonceSize, nil)
	if err != nil {
		return nil, err
	}

	_, err = nonceWriter.Write(pub1)
	if err != nil {
		return nil, err
	}

	_, err = nonceWriter.Write(pub2)
	if err != nil {
		return nil, err
	}

	nonceOut := nonceWriter.Sum(nil)
	copy(nonce[:], nonceOut)

	return &nonce, nil
}
