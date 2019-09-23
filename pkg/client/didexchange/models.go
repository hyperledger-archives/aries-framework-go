/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"time"
)

// QueryConnectionsParams model
//
// Parameters for querying connections
// TODO: this model is not final, to be updated as part of #226
//
type QueryConnectionsParams struct {

	// Alias of connection invitation
	Alias string `json:"alias,omitempty"`

	// Initiator is Connection invitation initiator
	Initiator string `json:"initiator,omitempty"`

	// Invitation key
	InvitationKey string `json:"invitation_key,omitempty"`

	// MyDID is DID of the agent
	MyDID string `json:"my_did,omitempty"`

	// State of the connection invitation
	State string `json:"state"`

	// TheirDID is other party's DID
	TheirDID string `json:"their_did,omitempty"`

	// TheirRole is other party's role
	TheirRole string `json:"their_role,omitempty"`
}

// QueryConnectionResult model
//
// This is used to represent query connection result
// TODO: this model is not final, to be updated as part of #226
//
// swagger:model QueryConnectionResult
type QueryConnectionResult struct {

	// State of the connection invitation
	State string `json:"state"`

	// TheirDID is other party's DID
	TheirDID string `json:"their_did"`

	// Created time
	CreatedTime time.Time `json:"created_at,omitempty"`

	// Connection invitation accept mode
	Accept string `json:"accept,omitempty"`

	// Alias of connection invitation
	Alias string `json:"alias,omitempty"`

	// TheirRole is other party's role
	TheirRole string `json:"their_role,omitempty"`

	// Initiator is Connection invitation initiator
	Initiator string `json:"initiator,omitempty"`

	// Updated time
	UpdatedTime time.Time `json:"updated_at,omitempty"`

	// Invitation key
	InvitationKey string `json:"invitation_key,omitempty"`

	// Routing state of connection invitation
	RoutingState string `json:"routing_state,omitempty"`

	// the connection ID of the connection invitation
	InboundConnectionID string `json:"inbound_connection_id,omitempty"`

	// the connection ID of the connection invitation
	ConnectionID string `json:"connection_id,omitempty"`

	// Error message
	Error string `json:"error_msg,omitempty"`

	// Invitation mode
	Mode string `json:"invitation_mode,omitempty"`
}
