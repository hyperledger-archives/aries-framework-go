/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

// CommandError contains a basic command Error.
type CommandError struct {
	Message string `json:"message"`
	Code    int    `json:"code,omitempty"`
	Type    int    `json:"type,omitempty"`
}

// RequestEnvelope contains a payload representing parameters for each operation on a protocol.
type RequestEnvelope struct {
	Payload []byte `json:"payload"`
}

// ResponseEnvelope contains a payload and an error from performing an operation on a protocol.
type ResponseEnvelope struct {
	Payload []byte        `json:"payload"`
	Error   *CommandError `json:"error,omitempty"`
}

// NewRequestEnvelope will return an instance of RequestEnvelope.
func NewRequestEnvelope(data []byte) *RequestEnvelope {
	return &RequestEnvelope{Payload: data}
}

// NewResponseEnvelope will return an instance of ResponseEnvelope.
func NewResponseEnvelope() *ResponseEnvelope {
	return &ResponseEnvelope{}
}
