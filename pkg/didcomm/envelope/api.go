/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package envelope

// Package envelope manages the handling of DIDComm raw messages in JWE compliant envelopes.
// The aim of this package is build these envelopes and parse them. They are mainly used as
// wire-level wrappers of 'payloads' used in DID Exchange flows.

// PackagerCreator method to create new outbound dispatcher service
type PackagerCreator func(prov Provider) (Packager, error)

// Packager provide methods to pack and unpack msg
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

// Envelope contain msg, FromVerKey and ToVerKeys
type Envelope struct {
	Message    []byte
	FromVerKey string
	// TODO add key type - issue #272
	ToVerKeys []string
}
