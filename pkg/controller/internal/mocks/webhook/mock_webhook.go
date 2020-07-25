/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webhook

// NewMockWebhookNotifier returns mock webhook notifier implementation.
func NewMockWebhookNotifier() *Notifier {
	return &Notifier{}
}

// Notifier is mock implementation of webhook notifier.
type Notifier struct {
	NotifyFunc func(topic string, message []byte) error
}

// Notify is mock implementation of webhook notifier Notify().
func (n *Notifier) Notify(topic string, message []byte) error {
	if n.NotifyFunc != nil {
		return n.NotifyFunc(topic, message)
	}

	return nil
}
