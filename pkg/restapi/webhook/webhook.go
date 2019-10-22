/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package webhook

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

const (
	notificationSendTimeout = 10 * time.Second
	emptyTopicErrMsg        = "cannot notify with an empty topic"
	emptyMessageErrMsg      = "cannot notify with an empty message"
)

var logger = log.New("aries-framework/agentd")

// Notifier represents a webhook dispatcher.
type Notifier interface {
	Notify(topic string, message []byte) error
}

// HTTPNotifier is a webhook dispatcher capable of notifying multiple subscribers via HTTP.
type HTTPNotifier struct {
	WebhookURLs []string
}

// NewHTTPNotifier returns a new instance of an HTTPNotifier.
func NewHTTPNotifier(webhookURLs []string) HTTPNotifier {
	return HTTPNotifier{WebhookURLs: webhookURLs}
}

// Notify sends the given message to all of the WebhookURLs.
// Topic is appended to the end of the webhook (subscriber) URL. E.g. localhost:8080/topic
// If multiple errors are encountered, then the first one is returned.
func (n HTTPNotifier) Notify(topic string, message []byte) error {
	if topic == "" {
		return fmt.Errorf(emptyTopicErrMsg)
	}

	if len(message) == 0 {
		return fmt.Errorf(emptyMessageErrMsg)
	}
	var allErrs error
	for _, webhookURL := range n.WebhookURLs {
		err := notify(fmt.Sprintf("%s%s%s", webhookURL, "/", topic), message)
		allErrs = appendError(allErrs, err)
	}
	return allErrs
}

func notify(destination string, message []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), notificationSendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, destination,
		bytes.NewBuffer(message))
	if err != nil {
		return fmt.Errorf("failed to create new http post request for %s: %s", destination, err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to post notification to %s: %s", destination, err)
	}

	defer closeResponse(resp.Body)

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		logger.Infof("Notification sent to %s successfully. \n", destination)
		return nil
	}
	return fmt.Errorf("notification was sent to %s, but %s was received",
		destination, resp.Status)
}

func closeResponse(c io.Closer) {
	err := c.Close()
	if err != nil {
		logger.Errorf("Failed to close response body")
	}
}

func appendError(errToAppendTo, err error) error {
	if errToAppendTo == nil {
		return err
	}
	return fmt.Errorf("%v;%v", errToAppendTo, err)
}
