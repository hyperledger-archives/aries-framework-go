/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package envelope

import baseenv "github.com/hyperledger/aries-framework-go/pkg/didcomm/envelope"

// BasePackager represents a mocked Packager
type BasePackager struct {
	PackValue   []byte
	PackErr     error
	UnpackValue *baseenv.Envelope
	UnpackErr   error
}

// PackMessage Pack a message for one or more recipients.
func (m *BasePackager) PackMessage(envelope *baseenv.Envelope) ([]byte, error) {
	return m.PackValue, m.PackErr
}

// UnpackMessage Unpack a message.
func (m *BasePackager) UnpackMessage(encMessage []byte) (*baseenv.Envelope, error) {
	return m.UnpackValue, m.UnpackErr
}
