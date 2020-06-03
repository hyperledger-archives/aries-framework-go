/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
)

// CreateRequestArgs model
//
// This is used for creating a request
//
type CreateRequestArgs struct {
	Label    string        `json:"label"`
	Goal     string        `json:"goal"`
	GoalCode string        `json:"goal_code"`
	Service  []interface{} `json:"service"`

	// Attachments is intended to provide the possibility to include files, links or even JSON payload to the message.
	Attachments []*decorator.Attachment `json:"attachments"`
}

// CreateRequestResponse model
//
// Represents a CreateRequest response message
//
type CreateRequestResponse struct {
	Request *outofband.Request `json:"request"`
}

// CreateInvitationArgs model
//
// This is used for creating an invitation
//
type CreateInvitationArgs struct {
	Label     string        `json:"label"`
	Goal      string        `json:"goal"`
	GoalCode  string        `json:"goal_code"`
	Service   []interface{} `json:"service"`
	Protocols []string      `json:"protocols"`
}

// CreateInvitationResponse model
//
// Represents a CreateInvitation response message
//
type CreateInvitationResponse struct {
	Invitation *outofband.Invitation `json:"invitation"`
}

// AcceptRequestArgs model
//
// This is used for accepting a request
//
type AcceptRequestArgs struct {
	Request *outofband.Request `json:"request"`
	MyLabel string             `json:"my_label"`
}

// AcceptRequestResponse model
//
// Represents a AcceptRequest response message
//
type AcceptRequestResponse struct {
	ConnectionID string `json:"connection_id"`
}

// AcceptInvitationArgs model
//
// This is used for accepting an invitation
//
type AcceptInvitationArgs struct {
	Invitation *outofband.Invitation `json:"invitation"`
	MyLabel    string                `json:"my_label"`
}

// AcceptInvitationResponse model
//
// Represents a AcceptInvitation response message
//
type AcceptInvitationResponse struct {
	ConnectionID string `json:"connection_id"`
}
