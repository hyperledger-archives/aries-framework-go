/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"errors"

	"golang.org/x/crypto/nacl/box"
)

// Decrypt will decode the envelope using the legacy format
// Using (X)Chacha20 encryption algorithm and Poly1035 authenticator
func (c *Crypter) Decrypt(envelope []byte, recipientPrivKey *privateEd25519) ([]byte, error) {
	// TODO implement legacy auth decrypt https://github.com/hyperledger/aries-framework-go/issues/294
	return nil, errors.New("not implemented")
}

// Open a box sealed by sodiumBoxSeal
func sodiumBoxSealOpen(msg []byte, recPub *publicCurve25519, recPriv *privateCurve25519) ([]byte, error) {
	if len(msg) < 32 {
		return nil, errors.New("message too short")
	}
	var epk [32]byte
	copy(epk[:], msg[:32])

	var nonce [24]byte
	nonceSlice, err := makeNonce(epk[:], recPub[:])
	if err != nil {
		return nil, err
	}
	copy(nonce[:], nonceSlice)

	out, success := box.Open(nil, msg[32:], &nonce, &epk, (*[32]byte)(recPriv))
	if !success {
		return nil, errors.New("failed to unpack")
	}

	return out, nil
}
