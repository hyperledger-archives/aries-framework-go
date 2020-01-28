/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

// Envelope for the DIDComm transport messages.
type Envelope struct {
	Protected  string `json:"protected,omitempty"`
	IV         string `json:"iv,omitempty"`
	CipherText string `json:"ciphertext,omitempty"`
	Tag        string `json:"tag,omitempty"`
}
