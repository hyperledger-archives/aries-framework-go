/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

// Service protocol service
type Service interface {
	Handle(msg DIDCommMsg) error
	Accept(msgType string) bool
	Name() string
}

// DIDCommMsg did comm msg
type DIDCommMsg struct {
	// Outbound indicates the direction of this DIDComm message:
	//   - outgoing (to another agent)
	//   - incoming (from another agent)
	Outbound bool
	Type     string
	Payload  []byte
}
