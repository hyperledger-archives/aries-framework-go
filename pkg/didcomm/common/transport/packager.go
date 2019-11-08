/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

// Packager manages the handling, building and parsing of DIDComm raw messages in JSON envelopes.
//
// These envelopes are used as wire-level wrappers of messages sent in Aries agent-agent communication.
type Packager interface {
	// PackMessage Pack a message for one or more recipients.
	//
	// Args:
	//
	// envelope: The message to pack
	//
	// Returns:
	//
	// []byte: The packed message
	//
	// error: error
	PackMessage(envelope *Envelope) ([]byte, error)

	// UnpackMessage Unpack a message.
	//
	// Args:
	//
	// encMessage: The encrypted message
	//
	// Returns:
	//
	// envelope: unpack message
	//
	// error: error
	UnpackMessage(encMessage []byte) (*Envelope, error)
}
