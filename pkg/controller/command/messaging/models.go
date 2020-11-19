/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messaging

import (
	"encoding/json"
	"time"
)

// RegisterMsgSvcArgs contains parameters for registering a message service to message handler.
type RegisterMsgSvcArgs struct {
	// Name of the message service
	Name string `json:"name"`

	// Acceptance criteria for message service based on message purpose
	// in case of multiple purposes, message will be dispatched if any one of the purpose matches
	// with the purpose of incoming message.
	// Can be provided in conjunction with other acceptance criteria.
	Purpose []string `json:"purpose"`

	// Acceptance criteria for message service based on message type.
	// Can be provided in conjunction with other acceptance criteria.
	Type string `json:"type"`
}

// UnregisterMsgSvcArgs contains parameters for unregistering a message service from message handler.
type UnregisterMsgSvcArgs struct {
	// Name of the message service to be unregistered
	// required: true
	Name string `json:"name"`
}

// RegisteredServicesResponse is for returning list of registered service names.
type RegisteredServicesResponse struct {
	// Registered service names
	Names []string `json:"names"`
}

// SendNewMessageArgs contains parameters for sending new message
// with one of three destination options below,
//	1. ConnectionID - ID of the connection between sender and receiver of this message.
//	2. TheirDID - TheirDID of the DID exchange connection record between sender and receiver of this message.
//	3. ServiceEndpoint (With recipient Keys, endpoint and optional routing keys) - To Send message outside connection.
// Note: Precedence logic when multiple destination options are provided are according to above order.
type SendNewMessageArgs struct {

	// Connection ID of the message destination
	// This parameter takes precedence over all the other destination parameters.
	ConnectionID string `json:"connection_ID,omitempty"`

	// DID of the destination.
	// This parameter takes precedence over `ServiceEndpoint` destination parameter.
	TheirDID string `json:"their_did,omitempty"`

	// ServiceEndpointDestination service endpoint destination.
	// This param can be used to send messages outside connection.
	ServiceEndpointDestination *ServiceEndpointDestinationParams `json:"service_endpoint,omitempty"`

	// Message body of the message
	MessageBody json.RawMessage `json:"message_body"`

	// Await reply from receiver of this message
	// If provided, then send message feature will wait response of this type for same thread
	AwaitReply AwaitReply `json:"await_reply"`
}

// ServiceEndpointDestinationParams contains service endpoint params.
type ServiceEndpointDestinationParams struct {
	// Recipient keys of service endpoint
	RecipientKeys []string `json:"recipientKeys,omitempty"`

	// Service endpoint
	ServiceEndpoint string `json:"serviceEndpoint,omitempty"`

	// Routing Keys of service endpoint
	RoutingKeys []string `json:"routingKeys,omitempty"`
}

// AwaitReply contains await for reply parameters.
type AwaitReply struct {
	// ReplyMessageType message type of incoming reply
	ReplyMessageType string `json:"messageType,omitempty"`
	// Timeout (in milliseconds) waiting for reply
	Timeout time.Duration `json:"timeout,omitempty"`
}

// SendReplyMessageArgs contains parameters for sending message reply.
type SendReplyMessageArgs struct {
	// ID of the message replying to
	MessageID string `json:"message_ID"`

	// Message body of the reply message
	MessageBody json.RawMessage `json:"message_body"`

	// StartNewThread if provided, replies to message by starting a new thread.
	StartNewThread bool `json:"start_new_thread"`

	// Await reply from receiver of this message
	// If provided, then reply message feature will wait response of this type for same thread
	AwaitReply AwaitReply `json:"await_reply"`
}

// SendMessageResponse is response for send/reply message feature.
type SendMessageResponse struct {
	// Response will contain raw message reply content if AwaitReply is used in send message request.
	Response json.RawMessage `json:"response,omitempty"`
}

// RegisterHTTPMsgSvcArgs contains parameters for registering an HTTP over DIDComm message service to message handler.
type RegisterHTTPMsgSvcArgs struct {
	// Name of the HTTP over DIDComm message service
	Name string `json:"name"`

	// Acceptance criteria for http over did comm message service based on message purpose.
	// In case of multiple purposes, operation will follow `A tagging system` purpose field validation from RFC-0351
	// If not provided then all incoming messages of HTTP over DIDComm type will be handled by operation.
	Purpose []string `json:"purpose"`
}
