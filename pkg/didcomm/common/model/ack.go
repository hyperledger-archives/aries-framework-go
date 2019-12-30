/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"

// Ack acknowledgement struct
type Ack struct {
	service.Header
	Status string `json:"status,omitempty"`
}
