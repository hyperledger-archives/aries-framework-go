/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
)

// outofbandCreateRequest model
//
// This is used for operation to create a request.
//
// swagger:parameters outofbandCreateRequest
type outofbandCreateRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Label    string        `json:"label"`
		Goal     string        `json:"goal"`
		GoalCode string        `json:"goal_code"`
		Service  []interface{} `json:"service"`
		// Attachments is intended to provide the possibility to include files, links or even JSON payload to the message.
		// required: true
		Attachments []*decorator.Attachment `json:"attachments"`
	}
}

// outofbandCreateRequestResponse model
//
// Represents a CreateRequest response message.
//
// swagger:response outofbandCreateRequestResponse
type outofbandCreateRequestResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Request *protocol.Request `json:"request"`
	}
}

// outofbandCreateInvitationRequest model
//
// This is used for operation to create an invitation.
//
// swagger:parameters outofbandCreateInvitation
type outofbandCreateInvitationRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Label     string        `json:"label"`
		Goal      string        `json:"goal"`
		GoalCode  string        `json:"goal_code"`
		Service   []interface{} `json:"service"`
		Protocols []string      `json:"protocols"`
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
		Invitation *protocol.Invitation `json:"invitation"`
	}
}

// outofbandAcceptRequest model
//
// This is used for operation to accept a request.
//
// swagger:parameters outofbandAcceptRequest
type outofbandAcceptRequest struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Request *protocol.Request `json:"request"`
		MyLabel string            `json:"my_label"`
	}
}

// outofbandAcceptRequestResponse model
//
// Represents a AcceptRequest response message.
//
// swagger:response outofbandAcceptRequestResponse
type outofbandAcceptRequestResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		ConnectionID string `json:"connection_id"`
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
		Invitation *protocol.Invitation `json:"invitation"`
		MyLabel    string               `json:"my_label"`
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
