/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

// HandshakeReuse is this protocol's 'handshake-reuse' message.
type HandshakeReuse struct {
	ID   string `json:"@id"`
	Type string `json:"@type"`
}

// HandshakeReuseAccepted is this protocol's 'handshake-reuse-accepted' message.
type HandshakeReuseAccepted struct {
	ID   string `json:"@id"`
	Type string `json:"@type"`
}
