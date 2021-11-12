/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
)

// CreateInvitationArgs model
//
// This is used for creating an invitation.
//
type CreateInvitationArgs struct {
	Label              string        `json:"label"`
	Goal               string        `json:"goal"`
	GoalCode           string        `json:"goal_code"`
	Service            []interface{} `json:"service"`
	Protocols          []string      `json:"protocols"`
	Accept             []string      `json:"accept"`
	RouterConnectionID string        `json:"router_connection_id"`
	// Attachments is intended to provide the possibility to include files, links or even JSON payload to the message.
	Attachments []*decorator.Attachment `json:"attachments"`
}

// CreateInvitationResponse model
//
// Represents a CreateInvitation response message.
//
type CreateInvitationResponse struct {
	Invitation *outofband.Invitation `json:"invitation"`
}

// AcceptInvitationArgs model
//
// This is used for accepting an invitation.
//
type AcceptInvitationArgs struct {
	Invitation         *outofband.Invitation `json:"invitation"`
	MyLabel            string                `json:"my_label"`
	RouterConnections  string                `json:"router_connections"`
	ReuseConnection    string                `json:"reuse_connection"`
	ReuseAnyConnection bool                  `json:"reuse_any_connection"`
}

// AcceptInvitationResponse model
//
// Represents a AcceptInvitation response message.
//
type AcceptInvitationResponse struct {
	ConnectionID string `json:"connection_id"`
}

// ActionStopArgs model
//
// This is used when action needs to be rejected.
//
type ActionStopArgs struct {
	// PIID Protocol instance ID
	PIID string `json:"piid"`
	// Reason why action is declined
	Reason string `json:"reason"`
}

// ActionStopResponse model
//
// Represents a ActionStop response message.
//
type ActionStopResponse struct{}

// ActionsResponse model
//
// Represents Actions response message.
//
type ActionsResponse struct {
	Actions []outofband.Action `json:"actions"`
}

// ActionContinueArgs model
//
// This is used when we need to proceed with the protocol.
//
type ActionContinueArgs struct {
	// PIID Protocol instance ID
	PIID              string `json:"piid"`
	Label             string `json:"label"`
	RouterConnections string `json:"router_connections"`
}

// ActionContinueResponse model
//
// Represents a ActionContinue response message.
//
type ActionContinueResponse struct{}
