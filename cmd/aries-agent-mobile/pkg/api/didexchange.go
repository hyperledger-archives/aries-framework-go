/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import "github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"

// DIDExchangeController  defines methods for the DIDExchange protocol controller.
type DIDExchangeController interface {

	// CreateInvitation creates a new connection invitation.
	CreateInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// ReceiveInvitation receives a new connection invitation.
	ReceiveInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptInvitation accepts a stored connection invitation.
	AcceptInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// CreateImplicitInvitation creates implicit invitation using inviter DID.
	CreateImplicitInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptExchangeRequest accepts a stored connection request.
	AcceptExchangeRequest(request *models.RequestEnvelope) *models.ResponseEnvelope

	// QueryConnections queries agent to agent connections.
	QueryConnections(request *models.RequestEnvelope) *models.ResponseEnvelope

	// QueryConnectionByID fetches a single connection record by connection ID.
	QueryConnectionByID(request *models.RequestEnvelope) *models.ResponseEnvelope

	// CreateConnection creates a new connection record in completed state and returns the generated connectionID.
	CreateConnection(request *models.RequestEnvelope) *models.ResponseEnvelope

	// RemoveConnection removes given connection record.
	RemoveConnection(request *models.RequestEnvelope) *models.ResponseEnvelope
}
