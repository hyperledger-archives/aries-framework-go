/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package decorator

import "time"

const (
	// TransportReturnRouteNone return route option none
	TransportReturnRouteNone = "none"

	// TransportReturnRouteAll return route option all
	TransportReturnRouteAll = "all"

	// TransportReturnRouteThread return route option thread
	TransportReturnRouteThread = "thread"
)

// Thread thread data
type Thread struct {
	ID  string `json:"thid,omitempty"`
	PID string `json:"pthid"`
}

// Timing keeps expiration time
type Timing struct {
	ExpiresTime time.Time `json:"expires_time,omitempty"`
}

// Transport transport decorator
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0092-transport-return-route
type Transport struct {
	ReturnRoute *ReturnRoute `json:"~transport,omitempty"`
}

// ReturnRoute works with Transport decorator. Acceptable values - "none", "all" or "thread".
type ReturnRoute struct {
	Value string `json:"~return_route,omitempty"`
}
