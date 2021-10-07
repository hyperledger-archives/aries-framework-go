/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messagepickup

// ProtocolService service interface for message pickup.
type ProtocolService interface {
	AddMessage(message []byte, theirDID string) error
}
