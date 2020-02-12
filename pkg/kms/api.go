/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package kms

// KeyManager manages keys and their storage for the aries framework
type KeyManager interface {
	// Create a new key/keyset/key handle for the type kt
	Create(kt string) (string, interface{}, error)
	// Get key handle for the given keyID
	Get(keyID string) (interface{}, error)
	// Rotate a key referenced by keyID and return a new handle of a keyset including old key and
	// new key with type kt. It also returns the updated keyID as the first return value
	Rotate(kt, keyID string) (string, interface{}, error)
}
