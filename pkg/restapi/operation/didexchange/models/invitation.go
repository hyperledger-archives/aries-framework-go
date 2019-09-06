/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
)

// A GenericError is the default error message that is generated.
// For certain status codes there are more appropriate error structures.
//
// swagger:response genericError
type GenericError struct {
	// in: body
	Body struct {
		Code    int32  `json:"code"`
		Message string `json:"message"`
	} `json:"body"`
}

// CreateInvitationResponse model
//
// This is used for returning a create invitation response with a single connection invitation as body
//
// swagger:response createInvitationResponse
type CreateInvitationResponse struct {

	// in: body
	Payload *didexchange.InvitationRequest `json:""`
}

// ReceiveInvitationRequest model
//
// This is used for operation to receive connection invitation
//
// swagger:parameters receiveInvitation
type ReceiveInvitationRequest struct {
	// The Invitation Request to receive
	//
	// required: true
	// in: body
	Params *ReceiveInvitationParams `json:"invitation"`
}

// ReceiveInvitationParams model
//
// This model defines DID exchange receive invitation parameters
//
// swagger:model ReceiveInvitationParams
type ReceiveInvitationParams struct {

	// the Type of the connection invitation
	Type string `json:"@type,omitempty"`

	// the ID of the connection invitation
	ID string `json:"@id"`

	// the Service endpoint of the connection invitation
	ServiceEndpoint string `json:"serviceEndpoint,omitempty"`

	// the Label of the connection invitation
	Label string `json:"label,omitempty"`

	// the RecipientKeys for the connection invitation
	RecipientKeys []string `json:"recipientKeys,omitempty"`
}

// ReceiveInvitationResponse model
//
// This is used for returning a receive invitation response with a single receive invitation response as body
//
// swagger:response receiveInvitationResponse
type ReceiveInvitationResponse struct {
	// State of the connection invitation
	State string `json:"state"`

	// Created time
	CreateTime time.Time `json:"created_at,omitempty"`

	// Updated time
	UpdateTime time.Time `json:"updated_at,omitempty"`

	// the connection ID of the connection invitation
	ConnectionID string `json:"connection_id"`

	// Routing state of connection invitation
	RoutingState string `json:"routing_state,omitempty"`

	// Connection invitation initiator
	Initiator string `json:"initiator,omitempty"`

	// Connection invitation accept mode
	Accept string `json:"accept,omitempty"`

	// Invitation mode
	Mode string `json:"invitation_mode,omitempty"`

	// Request ID of invitation response
	RequestID string `json:"request_id"`

	// My DID
	DID string `json:"my_did"`

	// Invitation key
	InvitationKey string `json:"invitation_key,omitempty"`

	// Other party's label
	InviterLabel string `json:"their_label,omitempty"`
}

// AcceptInvitationRequest model
//
// This is used for operation to accept connection invitation
//
// swagger:parameters acceptInvitation
type AcceptInvitationRequest struct {
	// The ID of Invitation Request to accept
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// AcceptInvitationResponse model
//
// This is used for returning a accept invitation response for single invitation
//
// swagger:response acceptInvitationResponse
type AcceptInvitationResponse struct {

	// State of the connection invitation
	State string `json:"state"`

	// Other party's DID
	InviterDID string `json:"their_did"`

	// Created time
	CreateTime time.Time `json:"created_at,omitempty"`

	// Connection invitation accept mode
	Accept string `json:"accept,omitempty"`

	// My DID
	DID string `json:"my_did"`

	// Request ID of invitation response
	RequestID string `json:"request_id"`

	// Other party's label
	InviterLabel string `json:"their_label,omitempty"`

	// Alias
	Alias string `json:"alias"`

	// Other party's role
	InviterRole string `json:"their_role"`

	// Connection invitation initiator
	Initiator string `json:"initiator,omitempty"`

	// Updated time
	UpdateTime time.Time `json:"updated_at,omitempty"`

	// Invitation key
	InvitationKey string `json:"invitation_key,omitempty"`

	// Routing state of connection invitation
	RoutingState string `json:"routing_state,omitempty"`

	// Inbound Connection ID  of the connection invitation
	InboundConnectionID string `json:"inbound_connection_id,omitempty"`

	// the connection ID of the connection invitation
	ConnectionID string `json:"connection_id"`

	// Error message
	Error string `json:"error_msg,omitempty"`

	// Invitation mode
	Mode string `json:"invitation_mode,omitempty"`
}
