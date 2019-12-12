/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

// Service protocol service
type Service interface {
	service.Handler
	Accept(msgType string) bool
	Name() string
}

// Outbound interface
type Outbound interface {
	Send(interface{}, string, *service.Destination) error
	SendToDID(msg interface{}, myDID, theirDID string) error
}
