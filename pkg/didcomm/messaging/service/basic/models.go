/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package basic

import "time"

// Message is message model for basic message protocol
// Reference:
//  https://github.com/hyperledger/aries-rfcs/tree/master/features/0095-basic-message#reference
type Message struct {
	ID   string `json:"@id"`
	Type string `json:"@type"`
	I10n struct {
		Locale string `json:"locale"`
	} `json:"~l10n"`
	SentTime time.Time `json:"sent_time"`
	Content  string    `json:"content"`
}
