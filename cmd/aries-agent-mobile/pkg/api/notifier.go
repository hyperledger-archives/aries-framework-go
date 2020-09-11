/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package api

// Notifier represents a notification dispatcher.
type Notifier interface {

	// Notify sends the given message to all of the subscribers.
	Notify(topic string, message []byte) error

	// GetPayload returns the payload message.
	GetPayload() []byte
}
