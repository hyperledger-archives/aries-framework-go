/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

// Forward route forward message.
// nolint:lll // url in the next line is long
// https://github.com/hyperledger/aries-rfcs/blob/master/concepts/0094-cross-domain-messaging/README.md#corerouting10forward
type Forward struct {
	Type string    `json:"@type,omitempty"`
	ID   string    `json:"@id,omitempty"`
	To   string    `json:"to,omitempty"`
	Msg  *Envelope `json:"msg,omitempty"`
}
