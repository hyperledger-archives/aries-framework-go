/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	vdrcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/vdr"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

const (
	vdrOperationID = "/vdr"
	createDIDPath  = vdrOperationID + "/did/create"
)

var logger = log.New("aries-framework/vdr-tests")

// ControllerSteps is steps for vdr with controller.
type ControllerSteps struct {
	bddContext *context.BDDContext
}

// NewVDRControllerSteps creates steps for vdr with controller.
func NewVDRControllerSteps() *ControllerSteps {
	return &ControllerSteps{}
}

// SetContext is called before every scenario is run with a fresh new context.
func (a *ControllerSteps) SetContext(ctx *context.BDDContext) {
	a.bddContext = ctx
}

// RegisterSteps registers agent steps.
func (a *ControllerSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" creates "([^"]*)" did through controller$`, a.createDID)
}

func (a *ControllerSteps) createDID(agentID, method string) error {
	url, ok := a.bddContext.GetControllerURL(agentID)
	if !ok {
		return fmt.Errorf("unable to find controller URL registered for agent [%s]",
			agentID)
	}

	didDocBytes, err := json.Marshal(vdrcmd.CreateDIDRequest{Method: method})
	if err != nil {
		return err
	}

	var result vdrcmd.Document

	err = util.SendHTTP(http.MethodPost, url+createDIDPath, didDocBytes, &result)
	if err != nil {
		logger.Errorf("Failed to create did, cause : %s", err)
		return err
	}

	if len(result.DID) == 0 {
		return fmt.Errorf("create did return empty result")
	}

	return nil
}
