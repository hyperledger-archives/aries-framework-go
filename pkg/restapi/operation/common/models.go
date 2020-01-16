/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// CreatePublicDIDRequest model
//
// This is used for operation to create public DID
//
// swagger:parameters createPublicDID
type CreatePublicDIDRequest struct {
	// Params for creating public DID
	//
	// in: path
	*CreatePublicDIDParams
}

// CreatePublicDIDParams contains parameters for creating new public DID
type CreatePublicDIDParams struct {
	// Params for creating public DID
	Method string `json:"method"`

	// RequestHeader to be included while submitting request to http binding URL
	RequestHeader string `json:"header"`
}

// CreatePublicDIDResponse model
//
// This is used for returning public DID created
//
// swagger:response createPublicDIDResponse
type CreatePublicDIDResponse struct {

	// in: body
	// TODO return base64-encoded raw bytes of the DID doc [Issue: #855]
	DID *did.Doc `json:"did"`
}

// RegisterMessageServiceRequest model
//
// This is used for operation to register a message service to message handler
//
// swagger:parameters registerMsgSvc
type RegisterMessageServiceRequest struct {
	// Params for registering message service
	//
	// in: body
	Params *RegisterMsgSvcParams
}

// RegisterMsgSvcParams contains parameters for registering a message service to message handler
type RegisterMsgSvcParams struct {
	// Name of the message service
	// required: true
	Name string `json:"name"`

	// Acceptance criteria for message service based on message purpose
	// in case of multiple purposes, message will be dispatched if any one of the purpose matches
	// with the purpose of incoming message.
	// Can be provided in conjunction with other acceptance criteria.
	Purpose []string `json:"purpose"`

	// Acceptance criteria for message service based on message type.
	// Can be provided in conjunction with other acceptance criteria.
	Type string `json:"type"`
}

// UnregisterMessageServiceRequest model
//
// This is used for operation to unregister a message service from message handler
//
// swagger:parameters unregisterMsgSvc
type UnregisterMessageServiceRequest struct {
	// Params for unregistering a message service
	//
	// in: body
	Params *UnregisterMsgSvcParams
}

// UnregisterMsgSvcParams contains parameters for unregistering a message service from message handler
type UnregisterMsgSvcParams struct {
	// Name of the message service to be unregistered
	// required: true
	Name string `json:"name"`
}

// RegisteredServicesResponse model
//
// This is used for returning list of registered service names
//
// swagger:response registeredServicesResponse
type RegisteredServicesResponse struct {
	// Registered service names
	//
	// in: body
	Names []string `json:"names"`
}
