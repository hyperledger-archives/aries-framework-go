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
	notificationInterval    = 2 * time.Second
	notificationSendTimeout = 10 * time.Second
)

var logger = log.New("aries-framework/agentd")

// StartWebhookDispatcher will launch the webhook dispatcher in a new goroutine.
// The dispatcher is responsible for sending notifications to subscribers.
func StartWebhookDispatcher(subscriberURLs []string) {
	if len(subscriberURLs) == 0 {
		logger.Warnf("No subscriber URLs provided. Webhook dispatcher will not start.")
		return
	}

	go dispatch(subscriberURLs)
}

func dispatch(subscriberURLs []string) {
	// TODO: Data should should be pushed whenever a record is created or its state property is updated  (see #472).
	ticker := time.NewTicker(notificationInterval)
	defer ticker.Stop()
	for range ticker.C {
		for _, subscriberURL := range subscriberURLs {
			err := sendNotification(subscriberURL)
			if err != nil {
				logger.Errorf(err.Error())
			}
		}
	}
}

func sendNotification(destination string) error {
	//TODO: This HTTP post request needs to supply real data, not this sample text (see #472).
	ctx, cancel := context.WithTimeout(context.Background(), notificationSendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, destination,
		bytes.NewBufferString("Sample notification from aries-agentd."))
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
