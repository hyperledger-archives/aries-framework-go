/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"

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

// Connection model
//
// This is used to represent query connection result
// TODO: this model is not final, to be updated as part of #226
//
// swagger:model Connection
type Connection struct {
	didexchange.ConnectionRecord
}
