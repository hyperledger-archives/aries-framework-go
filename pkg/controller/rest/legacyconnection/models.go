/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacyconnection

import (
	legacyConnSvc "github.com/hyperledger/aries-framework-go/pkg/client/legacyconnection"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/legacyconnection"
)

// legacyCreateInvitationRequest model
//
// This is used for operation to create invitation
//
// swagger:parameters legacyCreateInvitation
type legacyCreateInvitationRequest struct { // nolint: unused,deadcode
	// Params for creating invitation
	//
	// in: path
	legacyconnection.CreateInvitationArgs
}

// legacyCreateInvitationResponse model
//
// This is used for returning a create invitation response with a single connection invitation as body
//
// swagger:response legacyCreateInvitationResponse
type legacyCreateInvitationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Invitation    struct{ *legacyConnSvc.Invitation } `json:"invitation"`
		Alias         string                              `json:"alias"`
		InvitationURL string                              `json:"invitation_url"`
	}
}

// legacyReceiveInvitationRequest model
//
// This is used for operation to receive connection invitation
//
// swagger:parameters legacyReceiveInvitation
type legacyReceiveInvitationRequest struct { // nolint: unused,deadcode
	// The Invitation Invitation to receive
	//
	// required: true
	// in: body
	Invitation struct {
		*legacyConnSvc.Invitation
	}
}

// legacyReceiveInvitationResponse model
//
// This is used for returning a receive invitation response with a single receive invitation response as body
//
// swagger:response legacyReceiveInvitationResponse
type legacyReceiveInvitationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		legacyconnection.ReceiveInvitationResponse
	}
}

// legacyAcceptInvitationRequest model
//
// This is used for operation to accept connection invitation
//
// swagger:parameters legacyAcceptInvitation
type legacyAcceptInvitationRequest struct { // nolint: unused,deadcode
	// Connection ID
	//
	// in: path
	// required: true
	ID string `json:"id"`

	// Optional Public DID to be used for this request
	Public string `json:"public"`

	// Optional specifies router connections (comma-separated values)
	RouterConnections string `json:"router_connections"`
}

// legacyAcceptInvitationResponse model
//
// This is used for returning a accept invitation response for single invitation
//
// swagger:response legacyAcceptInvitationResponse
type legacyAcceptInvitationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		legacyconnection.AcceptInvitationResponse
	}
}

// legacyImplicitInvitationRequest model
//
// This is used by invitee to create implicit invitation
//
// swagger:parameters legacyImplicitInvitation
type legacyImplicitInvitationRequest struct { // nolint: unused,deadcode
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

// legacyImplicitInvitationResponse model
//
// This is used for returning create implicit invitation response
//
// swagger:response legacyImplicitInvitationResponse
type legacyImplicitInvitationResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		legacyconnection.ImplicitInvitationResponse
	}
}

// legacyGetConnectionRequest model
//
// This is used for getting specific connection record
//
// swagger:parameters legacyGetConnection
type legacyGetConnectionRequest struct { // nolint: unused,deadcode
	// The ID of the connection to get
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// legacyQueryConnections model
//
// This is used for querying connections
//
// swagger:parameters legacyQueryConnections
type legacyQueryConnections struct { // nolint: unused,deadcode
	// Params for querying connections
	//
	// in: path
	// required: true
	legacyConnSvc.QueryConnectionsParams
}

// legacyQueryConnectionResponse model
//
// This is used for returning query connection result for single record search
//
// swagger:response legacyQueryConnectionResponse
type legacyQueryConnectionResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Result *legacyConnSvc.Connection `json:"result,omitempty"`
	}
}

// legacyQueryConnectionsResponse model
//
// This is used for returning query connections results
//
// swagger:response legacyQueryConnectionsResponse
type legacyQueryConnectionsResponse struct { // nolint: unused,deadcode

	// in: body
	Body struct {
		Results []*legacyConnSvc.Connection `json:"results,omitempty"`
	}
}

// legacyAcceptConnectionRequestParams model
//
// This is used for accepting connection request
//
// swagger:parameters legacyAcceptRequest
type legacyAcceptConnectionRequestParams struct { // nolint: unused,deadcode
	// Connection ID
	//
	// in: path
	// required: true
	ID string `json:"id"`

	// Optional Public DID to be used for this invitation
	// request
	Public string `json:"public"`

	// Optional specifies router connections (comma-separated values)
	RouterConnections string `json:"router_connections"`
}

// legacyAcceptConnectionResult model
//
// This is used for returning response for accept Connection request
//
// swagger:response legacyAcceptConnectionResponse
type legacyAcceptConnectionResult struct { // nolint: unused,deadcode

	// in: body
	Result legacyconnection.ConnectionResponse
}

// LegacyRemoveConnectionRequest model
//
// This is used for removing connection request
//
// swagger:parameters legacyRemoveConnection
type LegacyRemoveConnectionRequest struct {
	// The ID of the connection record to remove
	//
	// in: path
	// required: true
	ID string `json:"id"`
}

// LegacyRemoveConnectionResponse model
//
// response of remove connection action
//
// swagger:response legacyRemoveConnectionResponse
type LegacyRemoveConnectionResponse struct {
	// in: body
	Body struct{}
}

// legacyCreateConnectionResp model
//
// This is used as the response model for save connection api.
//
// swagger:response legacyCreateConnectionResp
type legacyCreateConnectionResp struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// The ID of the connection to get
		//
		ID string `json:"id"`
	}
}

// legacyCreateConnectionRequest model
//
// Request to create a new connection between two DIDs.
//
// swagger:parameters legacyCreateConnection
type legacyCreateConnectionRequest struct { // nolint: unused,deadcode
	// Params for creating a connection.
	//
	// in: body
	// required: true
	Request legacyconnection.CreateConnectionRequest
}
