/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/config"
	opintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/rest/introduce"
	opverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/rest/verifiable"
)

// AriesREST is an Aries implementation with endpoints to execute operations
type AriesREST struct {
	endpoints map[string]map[string]*Endpoint

	URL   string
	Token string
}

// NewAries returns a new AriesREST instance.
// Use this if you want your requests to be handled by a remote agent.
func NewAries(opts *config.Options) *AriesREST {
	endpoints := getProtocolEndpoints()

	return &AriesREST{endpoints: endpoints, URL: opts.URL, Token: opts.APIToken}
}

// GetIntroduceController returns an IntroduceREST instance
func (ar *AriesREST) GetIntroduceController() (api.IntroduceController, error) {
	endpoints, ok := ar.endpoints[opintroduce.OperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for protocol [%s]", opintroduce.OperationID)
	}

	return &IntroduceREST{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}

// GetVerifiableController returns an VerifiableREST instance
func (ar *AriesREST) GetVerifiableController() (api.VerifiableController, error) {
	endpoints, ok := ar.endpoints[opverifiable.VerifiableOperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for protocol [%s]", opverifiable.VerifiableOperationID)
	}

	return &VerifiableREST{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}
