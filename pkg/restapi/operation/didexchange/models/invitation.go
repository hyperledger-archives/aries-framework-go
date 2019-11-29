/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
)

// CreateInvitationRequest model
//
// This is used for operation to create invitation
//
// swagger:parameters createInvitation
type CreateInvitationRequest struct {
	// Params for creating invitation
	//
	// in: path
	*CreateInvitationParams
}

// CreateInvitationParams model
//
// This is used for creating invitation
//
type CreateInvitationParams struct {

	// The Alias to be used in invitation to be created
	Alias string `json:"alias"`

	// Optional public DID to be used in invitation
	Public string `json:"public,omitempty"`
}

// CreateInvitationResponse model
//
// This is used for returning a create invitation response with a single connection invitation as body
//
// swagger:response createInvitationResponse
type CreateInvitationResponse struct {

	// in: body
	Invitation *didexchange.Invitation `json:"invitation"`

	// in: body
	Alias string `json:"alias"`

	// in: body
	InvitationURL string `json:"invitation_url"`
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
	Invitation *didexchange.Invitation `json:""`
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
	// Connection ID
	//
	// in: path
	// required: true
	ID string `json:"id"`

	// Optional Public DID to be used for this request
	Public string `json:"public"`
}

// AcceptInvitationResponse model
//
// This is used for returning a accept invitation response for single invitation
//
// swagger:response acceptInvitationResponse
type AcceptInvitationResponse struct {

	// State of the connection invitation
	State string `json:"state,omitempty"`

	// Other party's DID
	InviterDID string `json:"their_did,omitempty"`

	// Created time
	CreateTime time.Time `json:"created_at,omitempty"`

	// Connection invitation accept mode
	Accept string `json:"accept,omitempty"`

	// My DID
	DID string `json:"my_did,omitempty"`

	// Request ID of invitation response
	RequestID string `json:"request_id,omitempty"`

	// Other party's label
	InviterLabel string `json:"their_label,omitempty"`

	// Alias
	Alias string `json:"alias,omitempty"`

	// Other party's role
	InviterRole string `json:"their_role,omitempty"`

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
	ConnectionID string `json:"connection_id,omitempty"`

	// Error message
	Error string `json:"error_msg,omitempty"`

	// Invitation mode
	Mode string `json:"invitation_mode,omitempty"`
}

// ImplicitInvitationRequest model
//
// This is used by invitee to create implicit invitation
//
// swagger:parameters implicitInvitation
type ImplicitInvitationRequest struct {
	// InviterDID
	// required: true
	InviterDID string `json:"their_did"`

	// Optional inviter label
	InviterLabel string `json:"their_label"`

	// Optional invitee did
	InviteeDID string `json:"my_did"`

	// Optional invitee label
	InviteeLabel string `json:"my_label"`
}

// ImplicitInvitationResponse model
//
// This is used for returning create implicit invitation response
//
// swagger:response implicitInvitationResponse
type ImplicitInvitationResponse struct {

	// the connection ID of the connection for implicit invitation
	ConnectionID string `json:"connection_id,omitempty"`
}

// GetConnectionRequest model
//
// This is used for getting specific connection record
//
// swagger:parameters getConnection
type GetConnectionRequest struct {
	// The ID of the connection to get
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// QueryConnections model
//
// This is used for querying connections
//
// swagger:parameters queryConnections
type QueryConnections struct {
	// Params for querying connections
	//
	// in: path
	// required: true
	*didexchange.QueryConnectionsParams
}

// QueryConnectionResponse model
//
// This is used for returning query connection result for single record search
//
// swagger:response queryConnectionResponse
type QueryConnectionResponse struct {

	// in: body
	Result *didexchange.Connection `json:"result,omitempty"`
}

// QueryConnectionsResponse model
//
// This is used for returning query connections results
//
// swagger:response queryConnectionsResponse
type QueryConnectionsResponse struct {

	// in: body
	Results []*didexchange.Connection `json:"results,omitempty"`
}

// AcceptExchangeRequestParams model
//
// This is used for accepting connection request
//
// swagger:parameters acceptRequest
type AcceptExchangeRequestParams struct {
	// Connection ID
	//
	// in: path
	// required: true
	ID string `json:"id"`

	// Optional Public DID to be used for this invitation
	// request
	Public string `json:"public"`
}

// AcceptExchangeResult model
//
// This is used for returning response for accept exchange request
//
// swagger:response acceptExchangeResponse
type AcceptExchangeResult struct {

	// in: body
	Result *ExchangeResponse `json:""`
}

// ExchangeResponse model
//
// response of accept exchange request
//
// swagger:model ExchangeResponse
type ExchangeResponse struct {

	// Routing state of connection invitation
	RoutingState string `json:"routing_state,omitempty"`

	// the connection ID of the connection invitation
	InboundConnectionID string `json:"inbound_connection_id,omitempty"`

	// Invitation key
	InvitationKey string `json:"invitation_key,omitempty"`

	// TheirDID is other party's DID
	TheirDID string `json:"their_did"`

	// Request ID of the connection request
	RequestID string `json:"request_id"`

	// Invitation mode
	Mode string `json:"invitation_mode,omitempty"`

	// TheirRole is other party's role
	TheirRole string `json:"their_role,omitempty"`

	// TheirRole is other party's role
	TheirLabel string `json:"their_label,omitempty"`

	// the connection ID of the connection invitation
	ConnectionID string `json:"connection_id,omitempty"`

	// Initiator is Connection invitation initiator
	Initiator string `json:"initiator,omitempty"`

	// MyDID is DID of the agent
	MyDID string `json:"my_did,omitempty"`

	// Updated time
	UpdatedTime time.Time `json:"updated_at,omitempty"`

	// Created time
	CreatedTime time.Time `json:"created_at,omitempty"`

	// Error message
	Error string `json:"error_msg,omitempty"`

	// Alias of connection invitation
	Alias string `json:"alias,omitempty"`

	// State of the connection invitation
	State string `json:"state"`

	// Connection invitation accept mode
	Accept string `json:"accept,omitempty"`
}

// RemoveConnectionRequest model
//
// This is used for removing connection request
//
// swagger:parameters removeConnection
type RemoveConnectionRequest struct {
	// The ID of the connection record to remove
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// RemoveConnectionResponse model
//
// response of remove connection action
//
// swagger:response removeConnectionResponse
type RemoveConnectionResponse struct {
}
