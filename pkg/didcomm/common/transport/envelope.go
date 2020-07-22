/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

// Envelope holds message data and metadata for inbound and outbound messaging.
type Envelope struct {
	Message []byte
	FromKey []byte
	// ToKeys stores keys for an outbound message packing
	ToKeys []string
	// ToKey holds the key that was used to decrypt an inbound message
	ToKey   []byte
	FromDID string
	ToDID   string
}
