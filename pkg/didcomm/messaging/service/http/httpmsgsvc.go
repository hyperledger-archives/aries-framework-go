/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

// Package http provides http-over-didcomm message service features.
//
// Any incoming message of type "https://didcomm.org/http-over-didcomm/1.0/request" and matching purpose can be handled
// by registering 'OverDIDComm' message service.
//
// RFC Reference:
//
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0335-http-over-didcomm/README.md
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0351-purpose-decorator/README.md
//
package http

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
)

const (
	// OverDIDCommSpec is http over DIDComm Spec value.
	OverDIDCommSpec = "https://didcomm.org/http-over-didcomm/1.0/"

	// OverDIDCommMsgRequestType is http over DIDComm request message type.
	OverDIDCommMsgRequestType = OverDIDCommSpec + "request"

	// error messages.
	errNameAndHandleMandatory   = "service name and http request handle is mandatory"
	errFailedToDecodeMsg        = "unable to decode DID comm message: %w"
	errFailedToDecodeBody       = "unable to decode message body: %w"
	errFailedToCreateNewRequest = "failed to create http request from incoming message: %w"

	httpMessage = "httpMessage"
)

var logger = log.New("aries-framework/httpmsg")

// RequestHandle handle function for http over did comm message service which gets called by
// `OverDIDComm` message service to handle matching incoming request.
//
// Args
//
// msgID : message ID of incoming message.
// request: http request derived from incoming DID comm message.
//
// Returns
//
// error : handle can return error back to service to notify message dispatcher about failures.
type RequestHandle func(msgID string, request *http.Request) error

// NewOverDIDComm creates new HTTP over DIDComm message service which serves
// incoming DIDComm message over HTTP. DIDComm message receiver of [RFC-0351]
//
// Reference:
//
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0335-http-over-didcomm/README.md
// https://github.com/hyperledger/aries-rfcs/blob/master/features/0351-purpose-decorator/README.md
//
// Args:
//
// name - is name of this message service (this is mandatory argument).
//
// purpose - is optional list of purposes to be handled by this message service. If not provided then only message type
// will be taken into consideration in acceptance criteria of this message service.
//
// httpHandle - is handle function to which incoming DIDComm message will be sent after being converted to
// http request. (this is mandatory argument).
//
// Returns:
//
// OverDIDComm: http over didcomm message service,
//
// error: arg validation errors.
func NewOverDIDComm(name string, httpHandle RequestHandle, purpose ...string) (*OverDIDComm, error) {
	if name == "" || httpHandle == nil {
		return nil, fmt.Errorf(errNameAndHandleMandatory)
	}

	return &OverDIDComm{
		name:       name,
		purpose:    purpose,
		httpHandle: httpHandle,
	}, nil
}

// OverDIDComm is message service which transports incoming DIDComm message over to
// intended http resource providers.
type OverDIDComm struct {
	name       string
	purpose    []string
	httpHandle RequestHandle
}

// Name of HTTP over DIDComm message service.
func (m *OverDIDComm) Name() string {
	return m.name
}

// Accept is acceptance criteria for this HTTP over DIDComm message service,
// it accepts http-didcomm-over message type [RFC-0335] and follows `A tagging system` purpose field validation
// from RFC-0351.
func (m *OverDIDComm) Accept(msgType string, purpose []string) bool {
	if msgType != OverDIDCommMsgRequestType {
		return false
	}

	// if purpose not set, then match only message type.
	if len(m.purpose) == 0 {
		return true
	}

	// match purpose if provided
	for _, msgPurpose := range purpose {
		for _, svcPurpose := range m.purpose {
			if msgPurpose == svcPurpose {
				return true
			}
		}
	}

	return false
}

// HandleInbound for HTTP over DIDComm message service.
func (m *OverDIDComm) HandleInbound(msg service.DIDCommMsg, _ service.DIDCommContext) (string, error) {
	svcMsg := httpOverDIDCommMsg{}

	err := msg.Decode(&svcMsg)
	if err != nil {
		return "", fmt.Errorf(errFailedToDecodeMsg, err)
	}

	rqBody, err := base64.StdEncoding.DecodeString(svcMsg.BodyB64)
	if err != nil {
		return "", fmt.Errorf(errFailedToDecodeBody, err)
	}

	// create request
	request, err := http.NewRequest(svcMsg.Method, svcMsg.ResourceURI, bytes.NewBuffer(rqBody))
	if err != nil {
		return "", fmt.Errorf(errFailedToCreateNewRequest, err)
	}

	// add headers
	for _, header := range svcMsg.Headers {
		request.Header.Add(header.Name, header.Value)
	}

	logutil.LogDebug(logger, httpMessage, "handleInbound", "received",
		logutil.CreateKeyValueString("msgType", msg.Type()),
		logutil.CreateKeyValueString("msgID", msg.ID()))

	// TODO implement http version switch based on `msg.Version` [Issue:#1110]

	return "", m.httpHandle(msg.ID(), request)
}
