/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/config"
	opintroduce "github.com/hyperledger/aries-framework-go/pkg/controller/rest/introduce"
	opverifiable "github.com/hyperledger/aries-framework-go/pkg/controller/rest/verifiable"
)

// Aries is an Aries implementation with endpoints to execute operations
type Aries struct {
	endpoints map[string]map[string]*endpoint

	URL   string
	Token string
}

// NewAries returns a new Aries instance.
// Use this if you want your requests to be handled by a remote agent.
func NewAries(opts *config.Options) (*Aries, error) {
	if opts == nil || opts.AgentURL == "" {
		return nil, errors.New("no agent url provided")
	}

	endpoints := getProtocolEndpoints()

	return &Aries{endpoints: endpoints, URL: opts.AgentURL, Token: opts.APIToken}, nil
}

// GetIntroduceController returns an Introduce instance
func (ar *Aries) GetIntroduceController() (api.IntroduceController, error) {
	endpoints, ok := ar.endpoints[opintroduce.OperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for protocol [%s]", opintroduce.OperationID)
	}

	return &Introduce{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}

// GetVerifiableController returns an Verifiable instance
func (ar *Aries) GetVerifiableController() (api.VerifiableController, error) {
	endpoints, ok := ar.endpoints[opverifiable.VerifiableOperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for protocol [%s]", opverifiable.VerifiableOperationID)
	}

	return &Verifiable{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}
