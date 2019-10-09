/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

// Event properties related api.
type Event interface {
	// connection ID
	ConnectionID() string

	// invitation ID
	InvitationID() string
}
