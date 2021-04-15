/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

// QueryConnectionsParams model
//
// Parameters for querying connections.
//
type QueryConnectionsParams struct {

	// Alias of connection invitation
	Alias string `json:"alias,omitempty"`

	// Initiator is Connection invitation initiator
	Initiator string `json:"initiator,omitempty"`

	// Invitation key
	InvitationKey string `json:"invitation_key,omitempty"`

	// Invitation ID
	InvitationID string `json:"invitation_id,omitempty"`

	// Parent threadID
	ParentThreadID string `json:"parent_thread_id,omitempty"`

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
// This is used to represent query connection result.
//
type Connection struct {
	*connection.Record
}

// Invitation model for DID Exchange invitation.
type Invitation struct {
	*didexchange.Invitation
}

// DIDInfo model for specifying public DID and associated label.
type DIDInfo struct {

	// the DID
	DID string

	// the label associated with DID
	Label string
}
