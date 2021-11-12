/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

// SDKSteps is steps for JSON-LD operations using client SDK.
type SDKSteps struct {
	bddContext *context.BDDContext
	agent      *aries.Aries
}

// NewSDKSteps returns new steps for JSON-LD operations using client SDK.
func NewSDKSteps() *SDKSteps {
	return &SDKSteps{}
}

// SetContext is called before every scenario is run with a fresh new context.
func (s *SDKSteps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps registers the BDD steps on the suite.
func (s *SDKSteps) RegisterSteps(suite *godog.Suite) {
	suite.Step(`^"([^"]*)" adds a new remote provider with endpoint "([^"]*)" using client$`, s.addRemoteProvider)
	suite.Step(`^"([^"]*)" context from the provider is in agent's JSON-LD context store$`, s.checkContextInStore)
}

func (s *SDKSteps) addRemoteProvider(agentID, endpoint string) error {
	agent := s.bddContext.Agents[agentID]

	ctx, err := agent.Context()
	if err != nil {
		return fmt.Errorf("get agent context: %w", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}

	_, err = ld.NewClient(ctx).AddRemoteProvider(endpoint, remote.WithHTTPClient(httpClient))
	if err != nil {
		return fmt.Errorf("add remote provider: %w", err)
	}

	s.agent = agent

	return nil
}

func (s *SDKSteps) checkContextInStore(contextURL string) error {
	ctx, err := s.agent.Context()
	if err != nil {
		return fmt.Errorf("get agent context: %w", err)
	}

	_, err = ctx.JSONLDContextStore().Get(contextURL)
	if err != nil {
		return fmt.Errorf("get context from store: %w", err)
	}

	return nil
}
