/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/net/context"
	"nhooyr.io/websocket/wsjson"

	bddcontext "github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

// SendHTTP sends HTTP request.
func SendHTTP(method, destination string, message []byte, result interface{}) error {
	// create request
	req, err := http.NewRequest(method, destination, bytes.NewBuffer(message))
	if err != nil {
		return fmt.Errorf("failed to create new http '%s' request for '%s', cause: %s", method, destination, err)
	}

	// set headers
	req.Header.Set("Content-Type", "application/json")

	// send http request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get response from '%s', cause :%s", destination, err)
	}

	// nolint: errcheck
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response from '%s', cause :%s", destination, err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get successful response from '%s', unexpected status code [%d], "+
			"and message [%s]", destination, resp.StatusCode, string(data))
	}

	if result == nil {
		return nil
	}

	return json.Unmarshal(data, &result)
}

// PullEventsFromWebSocket returns WebSocket event by given filter
// nolint: gocyclo
func PullEventsFromWebSocket(bdd *bddcontext.BDDContext, agentID string, filters ...Filter) (*Incoming, error) {
	const timeoutPullTopics = 30 * time.Second

	conn, ok := bdd.GetWebSocketConn(agentID)
	if !ok {
		return nil, fmt.Errorf("unable to get websocket conn for agent [%s]", agentID)
	}

	filter := &eventFilter{}

	for i := range filters {
		filters[i](filter)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutPullTopics)
	defer cancel()

	for {
		var incoming *Incoming

		if err := wsjson.Read(ctx, conn, &incoming); err != nil {
			return nil, fmt.Errorf("failed to get topics for agent '%s' : %w", agentID, err)
		}

		if filter.Topic != nil && incoming.Topic != *filter.Topic {
			continue
		}

		if filter.StateID != nil && incoming.Message.StateID != *filter.StateID {
			continue
		}

		if filter.Type != nil && incoming.Message.Type != *filter.Type {
			continue
		}

		if filter.PIID != nil && incoming.Message.Properties["piid"].(string) != *filter.PIID {
			continue
		}

		return incoming, nil
	}
}

type eventFilter struct {
	Topic   *string
	StateID *string
	Type    *string
	PIID    *string
}

// Filter is an option for the PullEventsFromWebSocket function.
type Filter func(*eventFilter)

// FilterTopic filters WebSocket events by topic.
func FilterTopic(val string) Filter {
	return func(filter *eventFilter) {
		filter.Topic = &val
	}
}

// FilterStateID filters WebSocket events by stateID.
func FilterStateID(val string) Filter {
	return func(filter *eventFilter) {
		filter.StateID = &val
	}
}

// FilterPIID filters WebSocket events by PIID.
func FilterPIID(val string) Filter {
	return func(filter *eventFilter) {
		filter.PIID = &val
	}
}

// FilterType filters WebSocket events by type.
func FilterType(val string) Filter {
	return func(filter *eventFilter) {
		filter.Type = &val
	}
}

// Incoming represents WebSocket event message.
type Incoming struct {
	ID      string `json:"id"`
	Topic   string `json:"topic"`
	Message struct {
		ProtocolName string
		Message      map[string]interface{}
		StateID      string
		Properties   map[string]interface{}
		Type         string
	} `json:"message"`
}
