/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
)

// outofbandCreateInvitationRequest model
//
// This is used for operation to create an invitation.
//
// swagger:parameters outofbandCreateInvitation
type outofbandCreateInvitationRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Label              string        `json:"label"`
		Goal               string        `json:"goal"`
		GoalCode           string        `json:"goal_code"`
		Service            []interface{} `json:"service"`
		Protocols          []string      `json:"protocols"`
		RouterConnectionID string        `json:"router_connection_id"`
		// Attachments is intended to provide the possibility to include files, links or even JSON payload to the message.
		// required: true
		Attachments []*decorator.Attachment `json:"attachments"`
	}
}

// outofbandCreateInvitationResponse model
//
// Represents a CreateInvitation response message.
//
// swagger:response outofbandCreateInvitationResponse
type outofbandCreateInvitationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Invitation struct{ *protocol.Invitation } `json:"invitation"`
	}
}

// outofbandAcceptInvitationRequest model
//
// This is used for operation to accept an invitation.
//
// swagger:parameters outofbandAcceptInvitation
type outofbandAcceptInvitationRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Invitation         struct{ *protocol.Invitation } `json:"invitation"`
		MyLabel            string                         `json:"my_label"`
		RouterConnections  string                         `json:"router_connections"`
		ReuseConnection    string                         `json:"reuse_connection"`
		ReuseAnyConnection bool                           `json:"reuse_any_connection"`
	}
}

// outofbandAcceptInvitationResponse model
//
// Represents a AcceptInvitation response message.
//
// swagger:response outofbandAcceptInvitationResponse
type outofbandResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		ConnectionID string `json:"connection_id"`
	}
}

// outofbandActionsRequest model
//
// Returns pending actions that have not yet to be executed or cancelled.
//
// swagger:parameters outofbandActions
type outofbandActionsRequest struct{} // nolint: unused,deadcode

// outofbandActionsResponse model
//
// Represents a Actions response message
//
// swagger:response outofbandActionsResponse
type outofbandActionsResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Actions []struct{ *protocol.Action } `json:"actions"`
	}
}

// outofbandActionContinueRequest model
//
// Allows continuing with the protocol after an action event was triggered.
//
// swagger:parameters outofbandActionContinue
type outofbandActionContinueRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	Label string `json:"label"`

	RouterConnections string `json:"router_connections"`
}

// outofbandActionContinueResponse model
//
// Represents a ActionContinue response message
//
// swagger:response outofbandActionContinueResponse
type outofbandActionContinueResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}

// outofbandActionStopRequest model
//
// Stops the protocol after an action event was triggered.
//
// swagger:parameters outofbandActionStop
type outofbandActionStopRequest struct { // nolint: unused,deadcode
	// Protocol instance ID
	//
	// in: path
	// required: true
	PIID string `json:"piid"`

	Reason string `json:"reason"`
}

// outofbandActionStopResponse model
//
// Represents a ActionStop response message
//
// swagger:response outofbandActionStopResponse
type outofbandActionStopResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct{}
}
