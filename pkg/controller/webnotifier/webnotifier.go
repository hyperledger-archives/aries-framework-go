/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webnotifier

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
)

const (
	notificationSendTimeout = 10 * time.Second
	emptyTopicErrMsg        = "cannot notify with an empty topic"
	emptyMessageErrMsg      = "cannot notify with an empty message"
	failedToCreateErrMsg    = "failed to create topic message : %w"
)

var logger = log.New("aries-framework/webnotifier")

// WebNotifier is a dispatcher capable of notifying multiple subscribers via HTTP Webhooks and WebSockets.
type WebNotifier struct {
	notifiers []command.Notifier
	handlers  []rest.Handler
}

// New returns a new instance of a WebNotifier.
func New(wsPath string, webhookURLs []string) *WebNotifier {
	webhook := NewHTTPNotifier(webhookURLs)
	ws := NewWSNotifier(wsPath)

	n := WebNotifier{
		notifiers: []command.Notifier{webhook, ws},
		handlers:  ws.GetRESTHandlers(),
	}

	return &n
}

// Notify sends the given message to all of the subscribers.
// If multiple errors are encountered, then the first one is returned.
func (n *WebNotifier) Notify(topic string, message []byte) error {
	var allErrs error

	for _, notifier := range n.notifiers {
		err := notifier.Notify(topic, message)
		allErrs = appendError(allErrs, err)
	}

	return allErrs
}

// GetRESTHandlers returns all REST handlers provided by notifier.
func (n *WebNotifier) GetRESTHandlers() []rest.Handler {
	return n.handlers
}

func appendError(errToAppendTo, err error) error {
	if errToAppendTo == nil {
		return err
	}

	return fmt.Errorf("%v;%v", errToAppendTo, err) //nolint:errorlint
}

// PrepareTopicMessage prepares topic message.
func PrepareTopicMessage(topic string, message []byte) ([]byte, error) {
	topicMsg := struct {
		ID      string          `json:"id"`
		Topic   string          `json:"topic"`
		Message json.RawMessage `json:"message"`
	}{
		ID:      uuid.New().String(),
		Topic:   topic,
		Message: message,
	}

	return json.Marshal(topicMsg)
}
