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
	Type    string
	Payload []byte
}
