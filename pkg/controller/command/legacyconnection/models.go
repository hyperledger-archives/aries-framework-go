/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacyconnection

import (
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/client/legacyconnection"
)

// CreateInvitationArgs model
//
// This is used for creating invitation.
//
type CreateInvitationArgs struct {

	// The Alias to be used in invitation to be created
	Alias string `json:"alias"`

	// Optional public DID to be used in invitation
	Public string `json:"public,omitempty"`

	// Optional specifies router connection id
	RouterConnectionID string `json:"router_connection_id"`
}

// CreateInvitationResponse model
//
// This is used for returning a create invitation response with a single connection invitation as body.
//
type CreateInvitationResponse struct {
	Invitation *legacyconnection.Invitation `json:"invitation"`

	Alias string `json:"alias"`

	InvitationURL string `json:"invitation_url"`
}

// ReceiveInvitationResponse model
//
// This is used for returning a receive invitation response with a single receive invitation response as body.
//
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

	// Invitation ID of invitation response
	RequestID string `json:"request_id"`

	// My DID
	DID string `json:"my_did"`

	// Invitation key
	InvitationKey string `json:"invitation_key,omitempty"`

	// Other party's label
	InviterLabel string `json:"their_label,omitempty"`
}

// AcceptInvitationArgs model
//
// This is used for operation to accept connection invitation.
//
type AcceptInvitationArgs struct {
	// Connection ID
	ID string `json:"id"`

	// Optional Public DID to be used for this request
	Public string `json:"public"`

	// Optional specifies router connections (comma-separated values)
	RouterConnections string `json:"router_connections"`
}

// AcceptInvitationResponse model
//
// This is used for returning a accept invitation response for single invitation.
//
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

	// Invitation ID of invitation response
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

// ImplicitInvitationArgs model
//
// This is used by invitee to create implicit invitation.
//
type ImplicitInvitationArgs struct {
	// InviterDID
	InviterDID string `json:"their_did"`

	// Optional inviter label
	InviterLabel string `json:"their_label"`

	// Optional invitee did
	InviteeDID string `json:"my_did"`

	// Optional invitee label
	InviteeLabel string `json:"my_label"`

	// Optional specifies router connections (comma-separated values)
	RouterConnections string `json:"router_connections"`
}

// ImplicitInvitationResponse model
//
// This is used for returning create implicit invitation response.
//
type ImplicitInvitationResponse struct {
	// the connection ID of the connection for implicit invitation
	ConnectionID string `json:"connection_id,omitempty"`
}

// GetConnectionRequest model
//
// This is used for getting specific connection record.
//
type GetConnectionRequest struct {
	// The ID of the connection to get
	ID string `json:"id"`
}

// QueryConnectionsArgs model
//
// This is used for querying connections.
//
type QueryConnectionsArgs struct {
	// Params for querying connections
	legacyconnection.QueryConnectionsParams
}

// QueryConnectionResponse model
//
// This is used for returning query connection result for single record search.
//
type QueryConnectionResponse struct {
	Result *legacyconnection.Connection `json:"result,omitempty"`
}

// QueryConnectionsResponse model
//
// This is used for returning query connections results.
//
type QueryConnectionsResponse struct {
	Results []*legacyconnection.Connection `json:"results,omitempty"`
}

// AcceptConnectionRequestArgs model
//
// This is used for accepting connection request.
//
type AcceptConnectionRequestArgs struct {
	// Connection ID
	ID string `json:"id"`

	// Optional Public DID to be used for this invitation
	// request
	Public string `json:"public"`

	// Optional specifies router connections (comma-separated values)
	RouterConnections string `json:"router_connections"`
}

// ConnectionResponse model
//
// response of accept connection request.
//
type ConnectionResponse struct {

	// Routing state of connection invitation
	RoutingState string `json:"routing_state,omitempty"`

	// the connection ID of the connection invitation
	InboundConnectionID string `json:"inbound_connection_id,omitempty"`

	// Invitation key
	InvitationKey string `json:"invitation_key,omitempty"`

	// TheirDID is other party's DID
	TheirDID string `json:"their_did"`

	// Invitation ID of the connection request
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
// This is used for removing connection request.
//
type RemoveConnectionRequest struct {
	// The ID of the connection record to remove
	ID string `json:"id"`
}

// ConnectionIDArg model
//
// This is used for querying/removing connection by ID.
//
type ConnectionIDArg struct {
	// Connection ID
	ID string `json:"id"`
}

// CreateConnectionRequest model
//
// This is used for creating connection request.
//
type CreateConnectionRequest struct {
	MyDID          string      `json:"myDID"`
	TheirDID       DIDDocument `json:"theirDID"`
	TheirLabel     string      `json:"theirLabel,omitempty"`
	InvitationID   string      `json:"invitationID,omitempty"`
	InvitationDID  string      `json:"invitationDID,omitempty"`
	ParentThreadID string      `json:"parentThreadID,omitempty"`
	ThreadID       string      `json:"threadID,omitempty"`
	Implicit       bool        `json:"implicit,omitempty"`
}

// DIDDocument model.
type DIDDocument struct {
	ID       string          `json:"id"`
	Contents json.RawMessage `json:"contents"`
}
