/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

// Record model.
type Record struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"`
}
