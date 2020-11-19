/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messaging

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
)

// registerMessageServiceRequest model
//
// This is used for operation to register a message service to message handler
//
// swagger:parameters registerMsgSvc
type registerMessageServiceRequest struct { // nolint: unused,deadcode
	// Params for registering message service
	//
	// in: body
	Params messaging.RegisterMsgSvcArgs
}

// unregisterMessageServiceRequest model
//
// This is used for operation to unregister a message service from message handler
//
// swagger:parameters unregisterMsgSvc
type unregisterMessageServiceRequest struct { // nolint: unused,deadcode
	// Params for unregistering a message service
	//
	// in: body
	Params messaging.UnregisterMsgSvcArgs
}

// sendNewMessageRequest model
//
// This is used for operation to send new message
//
// swagger:parameters sendNewMessage
type sendNewMessageRequest struct { // nolint: unused,deadcode
	// Params for sending new message
	//
	// in: body
	Params messaging.SendNewMessageArgs
}

// SendReplyMessageRequest model
//
// This is used for operation to send reply to message
//
// swagger:parameters sendReplyMessage
type SendReplyMessageRequest struct {
	// Params for sending message reply
	//
	// in: body
	Params messaging.SendReplyMessageArgs
}

// RegisterHTTPMessageServiceRequest model
//
// This is used for operation to register an HTTP over DIDComm message service to message handler
//
// swagger:parameters registerHttpMsgSvc
type registerHTTPMessageServiceRequest struct { // nolint: unused,deadcode
	// Params for registering http over did comm message service.
	//
	// in: body
	Params messaging.RegisterHTTPMsgSvcArgs
}

// RegisteredServicesResponse model
//
// This is used for returning list of registered service names
//
// swagger:response registeredServicesResponse
type registeredServicesResponse struct {
	// in: body
	messaging.RegisteredServicesResponse
}

// sendMessageResponse model
//
// Response of send/reply message features.
// Usually contains reply for the message sent if await reply feature is used.
//
// swagger:response sendMessageResponse
type sendMessageResponse struct { // nolint: unused,deadcode
	// in: body
	Response json.RawMessage `json:"response,omitempty"`
}
