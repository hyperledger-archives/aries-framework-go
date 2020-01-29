/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// CreatePublicDIDRequest model
//
// This is used for operation to create public DID
//
// swagger:parameters createPublicDID
type CreatePublicDIDRequest struct {
	// Params for creating public DID
	//
	// in: path
	*CreatePublicDIDParams
}

// CreatePublicDIDParams contains parameters for creating new public DID
type CreatePublicDIDParams struct {
	// Params for creating public DID
	Method string `json:"method"`

	// RequestHeader to be included while submitting request to http binding URL
	RequestHeader string `json:"header"`
}

// CreatePublicDIDResponse model
//
// This is used for returning public DID created
//
// swagger:response createPublicDIDResponse
type CreatePublicDIDResponse struct {

	// in: body
	// TODO return base64-encoded raw bytes of the DID doc [Issue: #855]
	DID *did.Doc `json:"did"`
}

// RegisterMessageServiceRequest model
//
// This is used for operation to register a message service to message handler
//
// swagger:parameters registerMsgSvc
type RegisterMessageServiceRequest struct {
	// Params for registering message service
	//
	// in: body
	Params *RegisterMsgSvcParams
}

// RegisterMsgSvcParams contains parameters for registering a message service to message handler
type RegisterMsgSvcParams struct {
	// Name of the message service
	// required: true
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

// UnregisterMessageServiceRequest model
//
// This is used for operation to unregister a message service from message handler
//
// swagger:parameters unregisterMsgSvc
type UnregisterMessageServiceRequest struct {
	// Params for unregistering a message service
	//
	// in: body
	Params *UnregisterMsgSvcParams
}

// UnregisterMsgSvcParams contains parameters for unregistering a message service from message handler
type UnregisterMsgSvcParams struct {
	// Name of the message service to be unregistered
	// required: true
	Name string `json:"name"`
}

// RegisteredServicesResponse model
//
// This is used for returning list of registered service names
//
// swagger:response registeredServicesResponse
type RegisteredServicesResponse struct {
	// Registered service names
	//
	// in: body
	Names []string `json:"names"`
}

// SendNewMessageRequest model
//
// This is used for operation to send new message
//
// swagger:parameters sendNewMessage
type SendNewMessageRequest struct {
	// Params for sending new message
	//
	// in: body
	Params *SendNewMessageParams
}

// SendNewMessageParams contains parameters for sending new message
// with one of three destination options below,
//	1. ConnectionID - ID of the connection between sender and receiver of this message.
//	2. TheirDID - TheirDID of the DID exchange connection record between sender and receiver of this message.
//	3. ServiceEndpoint (With recipient Keys, endpoint and optional routing keys) - To Send message outside connection.
// Note: Precedence logic when multiple destination options are provided are according to above order.
type SendNewMessageParams struct {

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
	// required: true
	MessageBody json.RawMessage `json:"message_body"`
}

// ServiceEndpointDestinationParams contains service endpoint params
type ServiceEndpointDestinationParams struct {
	// Recipient keys of service endpoint
	RecipientKeys []string `json:"recipientKeys,omitempty"`

	// Service endpoint
	ServiceEndpoint string `json:"serviceEndpoint,omitempty"`

	// Routing Keys of service endpoint
	RoutingKeys []string `json:"routingKeys,omitempty"`
}

// SendReplyMessageRequest model
//
// This is used for operation to send reply to message
//
// swagger:parameters sendReplyMessage
type SendReplyMessageRequest struct {
	// Params for sending message reply
	//
	// in: body
	Params *SendReplyMessageParams
}

// SendReplyMessageParams contains parameters for sending message reply
type SendReplyMessageParams struct {
	// ID of the message replying to
	// required: true
	MessageID string `json:"message_ID"`

	// Message body of the reply message
	// required: true
	MessageBody json.RawMessage `json:"message_body"`
}

// RegisterHTTPMessageServiceRequest model
//
// This is used for operation to register a HTTP over DIDComm message service to message handler
//
// swagger:parameters registerHttpMsgSvc
type RegisterHTTPMessageServiceRequest struct {
	// Params for registering http over did comm message service.
	//
	// in: body
	Params *RegisterHTTPMsgSvcParams
}

// RegisterHTTPMsgSvcParams contains parameters for registering a HTTP over DIDComm message service to message handler.
type RegisterHTTPMsgSvcParams struct {
	// Name of the HTTP over DIDComm message service
	// required: true
	Name string `json:"name"`

	// Acceptance criteria for http over did comm message service based on message purpose.
	// In case of multiple purposes, operation will follow `A tagging system` purpose field validation from RFC-0351
	// If not provided then all incoming messages of HTTP over DIDComm type will be handled by operation.
	Purpose []string `json:"purpose"`
}
