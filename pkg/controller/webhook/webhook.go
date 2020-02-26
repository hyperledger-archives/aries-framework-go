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
	"strings"
	"time"

	"nhooyr.io/websocket"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

const (
	notificationSendTimeout = 10 * time.Second
	emptyTopicErrMsg        = "cannot notify with an empty topic"
	emptyMessageErrMsg      = "cannot notify with an empty message"
)

var logger = log.New("aries-framework/webhook")

// Notifier represents a webhook dispatcher.
type Notifier interface {
	Notify(topic string, message []byte) error
}

// WebNotifier is a webhook dispatcher capable of notifying multiple subscribers via HTTP.
type WebNotifier struct {
	httpURLs []string
	wsURLS   []string
}

// NewWebNotifier returns a new instance of an WebNotifier.
func NewWebNotifier(webhookURLs []string) *WebNotifier {
	var httpURLS, wsURLS []string

	for _, url := range webhookURLs {
		if strings.HasPrefix(url, "ws://") || strings.HasPrefix(url, "wss://") {
			wsURLS = append(wsURLS, url)
		} else {
			httpURLS = append(httpURLS, url)
		}
	}

	return &WebNotifier{httpURLs: httpURLS, wsURLS: wsURLS}
}

// Notify sends the given message to all of the URLs.
// Topic is appended to the end of the webhook (subscriber) URL. E.g. localhost:8080/topic
// If multiple errors are encountered, then the first one is returned.
func (n WebNotifier) Notify(topic string, message []byte) error {
	if topic == "" {
		return fmt.Errorf(emptyTopicErrMsg)
	}

	if len(message) == 0 {
		return fmt.Errorf(emptyMessageErrMsg)
	}

	var allErrs error

	for _, url := range n.httpURLs {
		// TODO create and pass parent context [Issue #1361]
		err := notifyHTTP(fmt.Sprintf("%s/%s", url, topic), message)
		allErrs = appendError(allErrs, err)
	}

	for _, url := range n.wsURLS {
		// TODO create and pass parent context [Issue #1361]
		err := notifyWS(fmt.Sprintf("%s/%s", url, topic), message)
		allErrs = appendError(allErrs, err)
	}

	return allErrs
}

func notifyHTTP(destination string, message []byte) error {
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

func notifyWS(destination string, message []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), notificationSendTimeout)
	defer cancel()

	c, rs, err := websocket.Dial(ctx, destination, nil)
	if err != nil {
		return err
	}

	// TODO keeping the connection open until an inactivity period. [Issue #1361]
	defer func() {
		err = c.Close(websocket.StatusNormalClosure, "closing connection")
		if err != nil {
			logger.Errorf("failed close websocket connection : %s", err)
		}

		if rs != nil && rs.Body != nil {
			closeResponse(rs.Body)
		}
	}()

	w, err := c.Writer(ctx, websocket.MessageText)
	if err != nil {
		return err
	}

	_, err = w.Write(message)
	if err != nil {
		return err
	}

	defer closeResponse(w)

	return nil
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
