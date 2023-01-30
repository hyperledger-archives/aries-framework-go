/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webnotifier

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

// HTTPNotifier is a webhook dispatcher capable of notifying multiple subscribers via HTTP.
type HTTPNotifier struct {
	urls []string
}

// NewHTTPNotifier returns a new instance of an HTTPNotifier.
func NewHTTPNotifier(webhookURLs []string) *HTTPNotifier {
	return &HTTPNotifier{urls: webhookURLs}
}

// Notify sends the given message to all of the urls.
// Topic is appended to the end of the webhook (subscriber) URL. E.g. localhost:8080/topic
// If multiple errors are encountered, then the first one is returned.
func (n *HTTPNotifier) Notify(topic string, message []byte) error {
	if topic == "" {
		return fmt.Errorf(emptyTopicErrMsg)
	}

	if len(message) == 0 {
		return fmt.Errorf(emptyMessageErrMsg)
	}

	topicMsg, err := PrepareTopicMessage(topic, message)
	if err != nil {
		return fmt.Errorf(failedToCreateErrMsg, err)
	}

	var allErrs error

	for _, webhookURL := range n.urls {
		err := notifyWH(webhookURL, topicMsg)
		allErrs = appendError(allErrs, err)
	}

	return allErrs
}

func notifyWH(destination string, message []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), notificationSendTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, destination,
		bytes.NewBuffer(message))
	if err != nil {
		return fmt.Errorf("failed to create new http post request for %s: %w", destination, err)
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to post notification to %s: %w", destination, err)
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
