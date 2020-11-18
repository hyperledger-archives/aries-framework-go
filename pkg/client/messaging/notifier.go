/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messaging

// NotificationPayload represent notification payload.
type NotificationPayload struct {
	Topic string
	Raw   []byte
}

// FilterNotification filters incoming notifications.
type FilterNotification func(string, []byte) bool

// BasicNotifier is channel based implementation of basic notifier.
type BasicNotifier struct {
	connection chan<- NotificationPayload
	filter     FilterNotification
}

// NewNotifier return notifier instance.
func NewNotifier(connection chan NotificationPayload, filter FilterNotification) *BasicNotifier {
	if filter == nil {
		filter = func(string, []byte) bool { return true }
	}

	return &BasicNotifier{connection: connection, filter: filter}
}

// Notify sends the given message to the subscribers based on filter logic.
func (n *BasicNotifier) Notify(topic string, message []byte) error {
	if n.filter(topic, message) {
		n.connection <- NotificationPayload{
			Topic: topic,
			Raw:   message,
		}
	}

	return nil
}
