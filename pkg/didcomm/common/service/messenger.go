/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

// DIDCommMsg describes message interface.
type DIDCommMsg interface {
	ID() string
	SetID(id string, opts ...Opt)
	SetThread(thid, pthid string, opts ...Opt)
	UnsetThread()
	Type() string
	ThreadID() (string, error)
	ParentThreadID() string
	Clone() DIDCommMsgMap
	Metadata() map[string]interface{}
	Decode(v interface{}) error
}

// DIDCommContext holds information on the context in which a DIDCommMsg is being processed.
type DIDCommContext interface {
	MyDID() string
	TheirDID() string
	EventProperties
}

// NewDIDCommContext returns a new DIDCommContext with the given DIDs and properties.
func NewDIDCommContext(myDID, theirDID string, props map[string]interface{}) DIDCommContext {
	return &context{
		myDID:    myDID,
		theirDID: theirDID,
		props:    props,
	}
}

// EmptyDIDCommContext returns a DIDCommContext with no DIDs nor properties.
func EmptyDIDCommContext() DIDCommContext {
	return &context{props: make(map[string]interface{})}
}

type context struct {
	myDID    string
	theirDID string
	props    map[string]interface{}
}

func (c *context) MyDID() string {
	return c.myDID
}

func (c *context) TheirDID() string {
	return c.theirDID
}

func (c *context) All() map[string]interface{} {
	return c.props
}

// The messenger package is responsible for the handling of communication between agents.
// It takes care of threading, timing, etc.
// Each message that we are going to send should be DIDCommMsg type.
// e.g we have type model.Ack{Type: "type", ID: "id"}
// it should be converted to: map[@id:id @type:type]
// NOTE: The package modifies message data by JSON tag name according to aries-rfcs.
//       Fields like @id, ~thread , etc. are redundant and may be rewritten.

// Messenger provides methods for the communication.
type Messenger interface {
	// ReplyTo replies to the message by given msgID.
	// Keeps threadID in the *decorator.Thread.
	// Using this function means that communication will be on the same thread.
	//
	// Deprecated: Please do not use it anymore. The function can be removed in future release.
	ReplyTo(msgID string, msg DIDCommMsgMap, opts ...Opt) error

	// ReplyToMsg replies to the given message.
	// Keeps threadID in the *decorator.Thread.
	// Using this function means that communication will be on the same thread.
	ReplyToMsg(in, out DIDCommMsgMap, myDID, theirDID string, opts ...Opt) error

	// Send sends the message by starting a new thread.
	Send(msg DIDCommMsgMap, myDID, theirDID string, opts ...Opt) error

	// SendToDestination sends the message to given destination by starting a new thread.
	SendToDestination(msg DIDCommMsgMap, sender string, destination *Destination, opts ...Opt) error

	// ReplyToNested sends the message by starting a new thread.
	// Keeps parent threadID in the *decorator.Thread
	ReplyToNested(msg DIDCommMsgMap, opts *NestedReplyOpts) error
}

// MessengerHandler includes Messenger interface and Handle function to handle inbound messages.
type MessengerHandler interface {
	Messenger
	InboundMessenger
}

// InboundMessenger contains Handle function to handle inbound messages.
type InboundMessenger interface {
	// HandleInbound handles all inbound messages
	HandleInbound(msg DIDCommMsgMap, ctx DIDCommContext) error
}

// NestedReplyOpts options for performing `ReplyToNested` operation.
type NestedReplyOpts struct {
	// ThreadID is parent thread ID for nested reply,
	// if not provided then 'ThreadID' from message record will be used
	ThreadID string
	// MyDID for nested reply message,
	// if not provided then 'MyDID' from message record will be used
	MyDID string
	// TheirDID for nested reply message,
	// if not provided then 'TheirDID' from message record will be used
	TheirDID string
	// MsgID to which nested reply to be sent,
	// optional when all the above parameters are provided.
	//
	// Deprecated: Please do not use it anymore. The field can be removed in future release.
	MsgID string
	V     Version
}
