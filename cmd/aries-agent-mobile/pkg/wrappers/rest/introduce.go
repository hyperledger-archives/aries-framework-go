/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"fmt"
	"net/url"
	"path"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers"
)

// IntroduceREST contains an http client and endpoints for each of its operations
type IntroduceREST struct {
	httpClient httpClient
	endpoints  map[string]*Endpoint
}

// Actions returns unfinished actions for the async usage.
// This creates an http request based on the provided method arguments.
func (ir *IntroduceREST) Actions(actionsRequest *wrappers.IntroduceActionsRequest) *wrappers.IntroduceActionsResponse {
	actionsURL, err := url.Parse(actionsRequest.URL)
	if err != nil {
		return &wrappers.IntroduceActionsResponse{
			Error: &wrappers.CommandError{Message: fmt.Sprintf("failed to parse url [%s]: %v", actionsRequest.URL, err)},
		}
	}

	endpoint := ir.endpoints["Actions"]
	actionsURL.Path = path.Join(actionsURL.Path, endpoint.Path)

	resp, err := makeHTTPRequest(ir.httpClient, endpoint.Method, actionsURL.String(), actionsRequest.Token)
	if err != nil {
		return &wrappers.IntroduceActionsResponse{
			Error: &wrappers.CommandError{Message: fmt.Sprintf("failed to get actions: %v", err)},
		}
	}

	return &wrappers.IntroduceActionsResponse{ActionsResponse: resp}
}
