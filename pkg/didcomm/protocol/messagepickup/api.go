/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messagepickup

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
)

// ProtocolService fix
type ProtocolService interface {
	AddMessage(message *model.Envelope, theirDID string) error
}
