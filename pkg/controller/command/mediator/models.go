/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

// RegisterRoute contains parameters for registering/reconnecting router.
type RegisterRoute struct {
	ConnectionID string `json:"connectionID"`
}
