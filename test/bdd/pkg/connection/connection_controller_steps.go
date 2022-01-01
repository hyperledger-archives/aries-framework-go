/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/connection"
	didexcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
	connectionrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/connection"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	bddctx "github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/util"
)

const (
	createConnectionEndpoint = connectionrest.CreateConnectionV2Path
	connectionBasePath       = connectionrest.OperationID + "/"
	setConnectionToV2Path    = "/use-v2"
	rotateDIDPath            = "/rotate-did"
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
	suite.Step(`^"([^"]*)" rotates its connection to "([^"]*)" to a new peer DID using controller$`, s.RotateToPeerDID)
}

// HasDIDCommV2Connection gives each agent a DIDComm v2 connection with the other, using their available public DIDs.
func (s *ControllerSteps) HasDIDCommV2Connection(agent1, agent2 string) error {
	err := s.ConnectAgentToOther(agent1, agent2)
	if err != nil {
		return fmt.Errorf("connecting [%s] to [%s]: %w", agent1, agent2, err)
	}

	err = s.ConnectAgentToOther(agent2, agent1)
	if err != nil {
		return fmt.Errorf("connecting [%s] to [%s]: %w", agent2, agent1, err)
	}

	return nil
}

// ConnectAgentToOther connects 'agent' to another agent 'other', with the connection created only on the 'agent' side.
func (s *ControllerSteps) ConnectAgentToOther(agent, other string) error {
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

	s.bddContext.SaveConnectionID(agent, other, result.ConnectionID)

	return nil
}

// RotateToPeerDID rotates agent's connection to otherAgent to a new peer DID.
func (s *ControllerSteps) RotateToPeerDID(agent, otherAgent string) error { // nolint:funlen
	controllerURL, ok := s.bddContext.GetControllerURL(agent)
	if !ok {
		return fmt.Errorf(" unable to find controller URL registered for agent [%s]", agent)
	}

	connID := s.bddContext.GetConnectionID(agent, otherAgent)
	if connID == "" {
		return fmt.Errorf("Rotate-DID bdd step needs a connectionID saved to bdd context "+
			"for agent '%s' to agent '%s'", agent, otherAgent)
	}

	queryPath := controllerURL + connectionrest.OperationID + "/" + connID

	resp := &didexcmd.QueryConnectionResponse{}

	err := util.SendHTTP(http.MethodGet, queryPath, nil, &resp)
	if err != nil {
		return fmt.Errorf("getting connection record from agent [%s]: %w", agent, err)
	}

	if resp.Result == nil {
		return fmt.Errorf("no connection exists to given agent that can be rotated")
	}

	oldDID := resp.Result.MyDID

	oldDIDb64 := base64.StdEncoding.EncodeToString([]byte(oldDID))

	queryPath = controllerURL + "/vdr/did/resolve/" + oldDIDb64

	oldDocRes := did.DocResolution{}

	err = util.SendHTTP(http.MethodGet, queryPath, nil, &oldDocRes)
	if err != nil {
		return fmt.Errorf("resolving oldDID through agent [%s]: %w", agent, err)
	}

	kid := ""

	oldDoc := oldDocRes.DIDDocument

	if len(oldDoc.Authentication) != 0 {
		kid = oldDoc.Authentication[0].VerificationMethod.ID
	}

	path := controllerURL + connectionBasePath + connID + rotateDIDPath

	rotateResp := connection.RotateDIDResponse{}

	err = postToURL(path, connection.RotateDIDRequest{
		ID:            connID,
		KID:           kid,
		CreatePeerDID: true,
	}, &rotateResp)
	if err != nil {
		return fmt.Errorf("error in request to agent [%s] to rotate connection [%s] to peer DID: %w", agent, connID, err)
	}

	s.bddContext.PeerDIDs[agent] = rotateResp.NewDID
	s.bddContext.SaveConnectionID(agent, otherAgent, connID)

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

	return util.SendHTTP(http.MethodPost, url, body, resp)
}
