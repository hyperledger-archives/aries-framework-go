/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import "github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"

// MessagingController defines methods for the Messaging controller.
type MessagingController interface {

	// RegisterService registers new message service to message handler registrar.
	RegisterService(request *models.RequestEnvelope) *models.ResponseEnvelope

	// UnregisterService unregisters given message service handler registrar.
	UnregisterService(request *models.RequestEnvelope) *models.ResponseEnvelope

	// Services returns list of registered service names.
	Services(request *models.RequestEnvelope) *models.ResponseEnvelope

	// Send sends new message to destination provided.
	Send(request *models.RequestEnvelope) *models.ResponseEnvelope

	// Reply sends reply to existing message.
	Reply(request *models.RequestEnvelope) *models.ResponseEnvelope

	// RegisterHTTPService registers new http over didcomm service to message handler registrar.
	RegisterHTTPService(request *models.RequestEnvelope) *models.ResponseEnvelope
}
