/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/messagepickup"
)

// RegisterRoute contains parameters for registering/reconnecting router.
type RegisterRoute struct {
	ConnectionID string `json:"connectionID"`
}

// ConnectionsRequest contains parameters for filtering when requesting router connections.
type ConnectionsRequest struct {
	DIDCommV1Only bool `json:"didcomm_v1"`
	DIDCommV2Only bool `json:"didcomm_v2"`
}

// ConnectionsResponse is response for router`s connections.
type ConnectionsResponse struct {
	Connections []string `json:"connections"`
}

// StatusRequest is request for getting details about pending messages.
type StatusRequest struct {
	ConnectionID string `json:"connectionID"`
}

// StatusResponse is status response containing details about pending messages.
type StatusResponse struct {
	*messagepickup.Status
}

// BatchPickupRequest is request for dispatching pending messages.
type BatchPickupRequest struct {
	// ConnectionID of connection for which pending messages needs to be dispatched.
	ConnectionID string `json:"connectionID"`
	// Size of batch of pending messages to be dispatched.
	Size int `json:"batch_size"`
}

// BatchPickupResponse is response for dispatching pending messages.
type BatchPickupResponse struct {
	// Count of messages dispatched.
	MessageCount int `json:"message_count"`
}

// CreateInvitationRequest model
//
// This is used for creating an invitation using mediator.
//
type CreateInvitationRequest struct {
	Label     string        `json:"label"`
	Goal      string        `json:"goal"`
	GoalCode  string        `json:"goal_code"`
	Service   []interface{} `json:"service"`
	Protocols []string      `json:"protocols"`
}

// CreateInvitationResponse model
//
// Response for creating invitation through mediator.
//
type CreateInvitationResponse struct {
	// Invitation is out-of-band invitation from mediator.
	Invitation *outofband.Invitation `json:"invitation"`
}
