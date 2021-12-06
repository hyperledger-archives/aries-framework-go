/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/connection"
	connectionrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/connection"
	bddctx "github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

const (
	createConnectionEndpoint = connectionrest.CreateConnectionV2Path
	connectionBasePath       = connectionrest.OperationID + "/"
	setConnectionToV2Path    = "/use-v2"
)

// ControllerSteps holds connection BDD steps using AFGO's REST API.
type ControllerSteps struct {
	bddContext *bddctx.BDDContext
}

// NewControllerSteps creates connection Controller steps.
func NewControllerSteps() *ControllerSteps {
	return &ControllerSteps{}
}

// SetContext is called before every scenario is run with a fresh new bddctx.
func (s *ControllerSteps) SetContext(ctx *bddctx.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps registers the BDD steps on the suite.
func (s *ControllerSteps) RegisterSteps(suite *godog.Suite) {
	suite.Step(`^"([^"]*)" and "([^"]*)" have a DIDComm v2 connection using controller$`, s.HasDIDCommV2Connection)
}

// HasDIDCommV2Connection gives each agent a DIDComm v2 connection with the other, using their available public DIDs.
func (s *ControllerSteps) HasDIDCommV2Connection(agent1, agent2 string) error {
	err := s.connectAgentToOther(agent1, agent2)
	if err != nil {
		return fmt.Errorf("connecting [%s] to [%s]: %w", agent1, agent2, err)
	}

	err = s.connectAgentToOther(agent2, agent1)
	if err != nil {
		return fmt.Errorf("connecting [%s] to [%s]: %w", agent2, agent1, err)
	}

	return nil
}

func (s *ControllerSteps) connectAgentToOther(agent, other string) error {
	// TODO: consider using peer DIDs instead
	//  - create and import a priv key for each
	//  - create a peer DID for each
	//  - save each others' peer DIDs
	//  - perform connection with peer DIDs
	myDID, ok := s.bddContext.PublicDIDs[agent]
	if !ok {
		return fmt.Errorf("EMPTY MYDID")
	}

	theirDID, ok := s.bddContext.PublicDIDs[other]
	if !ok {
		return fmt.Errorf("EMPTY THEIRDID")
	}

	controllerURL, ok := s.bddContext.GetControllerURL(agent)
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", agent)
	}

	path := fmt.Sprintf("%s%s", controllerURL, createConnectionEndpoint)

	var result connection.IDMessage

	err := postToURL(path, connection.CreateConnectionRequest{
		MyDID:    myDID,
		TheirDID: theirDID,
	}, &result)
	if err != nil {
		return fmt.Errorf("error in create connection request to agent [%s]: %w", agent, err)
	}

	idMap, ok := s.bddContext.ConnectionIDs[agent]
	if !ok {
		s.bddContext.ConnectionIDs[agent] = make(map[string]string)
		idMap = s.bddContext.ConnectionIDs[agent]
	}

	idMap[other] = result.ConnectionID

	return nil
}

// SetConnectionToDIDCommV2 sets the given connection for the given agent to DIDComm V2.
func (s *ControllerSteps) SetConnectionToDIDCommV2(agent, connID string) error {
	controllerURL, ok := s.bddContext.GetControllerURL(agent)
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", agent)
	}

	path := fmt.Sprintf("%s%s%s%s", controllerURL, connectionBasePath, connID, setConnectionToV2Path)

	err := postToURL(path, connection.IDMessage{
		ConnectionID: connID,
	}, nil)
	if err != nil {
		return fmt.Errorf("error in request to agent [%s] to set connection [%s] to didcomm v2: %w", agent, connID, err)
	}

	return nil
}

func postToURL(url string, payload, resp interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshalling payload: %w", err)
	}

	if resp == nil {
		return util.SendHTTP(http.MethodPost, url, body, nil)
	}

	return util.SendHTTP(http.MethodPost, url, body, &resp)
}
