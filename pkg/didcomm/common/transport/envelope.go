/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

// Envelope holds message data and metadata for inbound and outbound messaging
type Envelope struct {
	Message    []byte
	FromVerKey []byte
	// ToVerKeys stores string (base58) verification keys for an outbound message
	ToVerKeys []string
	// ToVerKey holds the key that was used to decrypt an inbound message
	ToVerKey []byte
	FromDID  string
	ToDID    string
}
