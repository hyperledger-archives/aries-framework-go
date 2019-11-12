/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package decorator

import "time"

// Thread thread data
type Thread struct {
	ID  string `json:"thid,omitempty"`
	PID string `json:"pthid"`
}

// Timing keeps expiration time
type Timing struct {
	ExpiresTime time.Time `json:"expires_time,omitempty"`
}
