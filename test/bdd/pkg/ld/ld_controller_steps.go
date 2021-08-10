/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	_ "embed" //nolint:gci // required for go:embed
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cucumber/godog"

	ldcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

const (
	ldOperationID     = "/ld"
	addRemoteProvider = ldOperationID + "/remote-provider"

	validateCredential = "/verifiable/credential/validate"
)

//go:embed testdata/vaccination-certificate.jsonld
var vaccinationCertificate []byte // nolint:gochecknoglobals // embedded test VC

// ControllerSteps is steps for ld with controller.
type ControllerSteps struct {
	bddContext    *context.BDDContext
	controllerURL string
}

// NewLDControllerSteps creates steps for ld with controller.
func NewLDControllerSteps() *ControllerSteps {
	return &ControllerSteps{}
}

// SetContext is called before every scenario is run with a fresh new context.
func (a *ControllerSteps) SetContext(ctx *context.BDDContext) {
	a.bddContext = ctx
}

// RegisterSteps registers agent steps.
func (a *ControllerSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" adds a new remote provider with endpoint "([^"]*)" through controller$`, a.addRemoteProvider)
	s.Step(`^vaccination context from the provider is available to the agent instance$`, a.checkContext)
}

func (a *ControllerSteps) addRemoteProvider(agentID, endpoint string) error {
	controllerURL, ok := a.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]", agentID)
	}

	a.controllerURL = controllerURL

	reqBytes, err := json.Marshal(ldcmd.AddRemoteProviderRequest{Endpoint: endpoint})
	if err != nil {
		return fmt.Errorf("marshal add remote provider request: %w", err)
	}

	err = util.SendHTTP(http.MethodPost, controllerURL+addRemoteProvider, reqBytes, nil)
	if err != nil {
		return fmt.Errorf("send HTTP request to add new remote provider: %w", err)
	}

	return nil
}

// checkContext verifies if JSON-LD context "https://w3id.org/vaccination/v1" is available to the agent instance
// by validating vaccination certificate VC. The context itself should come from the newly added remote provider.
func (a *ControllerSteps) checkContext() error {
	reqBytes, err := json.Marshal(verifiable.Credential{
		VerifiableCredential: string(vaccinationCertificate),
	})
	if err != nil {
		return fmt.Errorf("marshal VC request: %w", err)
	}

	err = util.SendHTTP(http.MethodPost, a.controllerURL+validateCredential, reqBytes, nil)
	if err != nil {
		return fmt.Errorf("validate credential: %w", err)
	}

	return nil
}
