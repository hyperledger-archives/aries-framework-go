/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

// Event properties related api. This can be used to cast Generic event properties to DID Exchange specific props.
type Event interface {
	// connection ID
	ConnectionID() string

	// invitation ID
	InvitationID() string
}
