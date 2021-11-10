/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

// RotateDIDRequest request to rotate MyDID in the connection with the given ID.
type RotateDIDRequest struct {
	ID     string `json:"id"`
	KID    string `json:"kid"`
	NewDID string `json:"new_did"`
}
