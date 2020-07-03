/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"net/http"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers"
)

// Endpoint describes the fields for making calls to external agents
type Endpoint struct {
	Path   string
	Method string
	PIID   string
}

func getProtocolEndpoints() map[string]map[string]*Endpoint {
	allEndpoints := make(map[string]map[string]*Endpoint)

	allEndpoints[wrappers.ProtocolIntroduce] = getIntroduceEndpoints()

	return allEndpoints
}

func getIntroduceEndpoints() map[string]*Endpoint {
	return map[string]*Endpoint{
		"Actions": {
			Path:   "/introduce/actions",
			Method: http.MethodGet,
		},
	}
}
