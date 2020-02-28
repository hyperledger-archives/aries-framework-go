/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

// CredentialRecord model
type CredentialRecord struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"`
}
