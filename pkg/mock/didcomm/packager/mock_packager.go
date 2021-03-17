/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package packager

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

// Packager represents a mocked Packager.
type Packager struct {
	PackValue   []byte
	PackErr     error
	UnpackValue *transport.Envelope
	UnpackErr   error
}

// PackMessage Pack a message for one or more recipients.
func (m *Packager) PackMessage(e *transport.Envelope) ([]byte, error) {
	return m.PackValue, m.PackErr
}

// UnpackMessage Unpack a message.
func (m *Packager) UnpackMessage(encMessage []byte) (*transport.Envelope, error) {
	return m.UnpackValue, m.UnpackErr
}
