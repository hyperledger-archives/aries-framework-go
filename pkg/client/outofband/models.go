/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"

// Request is the out-of-band protocol's 'request' message.
type Request struct {
	*outofband.Request
}
