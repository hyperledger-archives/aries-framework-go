/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

// DIDCommMsg describes message interface
type DIDCommMsg interface {
	ID() string
	Type() string
	ThreadID() (string, error)
	ParentThreadID() string
	Clone() DIDCommMsgMap
	Metadata() map[string]interface{}
	Decode(v interface{}) error
}

// The messenger package is responsible for the handling of communication between agents.
// It takes care of threading, timing, etc.
// Each message that we are going to send should be DIDCommMsg type.
// e.g we have type model.Ack{Type: "type", ID: "id"}
// it should be converted to: map[@id:id @type:type]
// NOTE: The package modifies message data by JSON tag name according to aries-rfcs.
//       Fields like @id, ~thread , etc. are redundant and may be rewritten.

// Messenger provides methods for the communication
type Messenger interface {
	// ReplyTo replies to the message by given msgID.
	// Keeps threadID in the *decorator.Thread.
	// Using this function means that communication will be on the same thread.
	ReplyTo(msgID string, msg DIDCommMsgMap) error

	// Send sends the message by starting a new thread.
	Send(msg DIDCommMsgMap, myDID, theirDID string) error

	// ReplyToNested sends the message by starting a new thread.
	// Keeps parent threadID in the *decorator.Thread
	ReplyToNested(threadID string, msg DIDCommMsgMap, myDID, theirDID string) error
}

// MessengerHandler includes Messenger interface and Handle function to handle inbound messages
type MessengerHandler interface {
	Messenger
	// HandleInbound handles all inbound messages
	HandleInbound(msg DIDCommMsgMap, myDID, theirDID string) error
}
