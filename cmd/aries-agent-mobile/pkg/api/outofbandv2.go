/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import "github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"

// OutOfBandV2Controller defines methods for the out-of-band/2.0 protocol controller.
type OutOfBandV2Controller interface {
	// CreateInvitation creates and saves an out-of-band invitation.
	CreateInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope

	// AcceptInvitation from another agent and return the ID of the new connection records.
	AcceptInvitation(request *models.RequestEnvelope) *models.ResponseEnvelope
}
