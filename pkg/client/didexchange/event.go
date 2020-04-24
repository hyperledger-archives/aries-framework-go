/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"

// Event properties related api. This can be used to cast Generic event properties to DID Exchange specific props.
type Event didexchange.Event
