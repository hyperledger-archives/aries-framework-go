/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"fmt"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/client/connection"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	connection2 "github.com/hyperledger/aries-framework-go/pkg/store/connection"
	bddctx "github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/didresolver"
)

// SDKSteps holds connection BDD steps using AFGO's Go SDK.
type SDKSteps struct {
	bddContext *bddctx.BDDContext
}

// NewSDKSteps creates connection SDK steps.
func NewSDKSteps() *SDKSteps {
	return &SDKSteps{}
}

// SetContext is called before every scenario is run with a fresh new bddctx.
func (s *SDKSteps) SetContext(ctx *bddctx.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps registers the BDD steps on the suite.
func (s *SDKSteps) RegisterSteps(suite *godog.Suite) {
	suite.Step(`^"([^"]*)" rotates their connection to "([^"]*)" to new DID$`, s.rotateDID)
}

func (s *SDKSteps) rotateDID(agentID, otherAgent string) error { // nolint:gocyclo
	// TODO: find connectionID for connection to other agent (which is given by name, not by DID)
	// TODO: then call RotateDID.
	agentCtx := s.bddContext.AgentCtx[agentID]

	myDoc := s.bddContext.PublicDIDDocs[agentID]
	theirDoc := s.bddContext.PublicDIDDocs[otherAgent]

	didExClient, err := didexchange.New(agentCtx)
	if err != nil {
		return err
	}

	conns, err := didExClient.QueryConnections(&didexchange.QueryConnectionsParams{
		MyDID:    myDoc.ID,
		TheirDID: theirDoc.ID,
	})
	if err != nil {
		return fmt.Errorf("query connections: %w", err)
	}

	var connID string

	if len(conns) == 0 {
		connID, err = s.createConnection(agentCtx, myDoc.ID, theirDoc)
		if err != nil {
			return fmt.Errorf("create connection: %w", err)
		}
	} else {
		connID = conns[0].ConnectionID
	}

	myDoc, ok := s.bddContext.PublicDIDDocs[agentID]
	if !ok || myDoc == nil {
		return fmt.Errorf("can't rotate without a DID doc to rotate from")
	}

	if len(myDoc.Authentication) == 0 {
		return fmt.Errorf("can't rotate if the prior doc has no authentication key")
	}

	authKID := myDoc.Authentication[0].VerificationMethod.ID

	err = didresolver.CreateDIDDocument(s.bddContext, agentID, "")
	if err != nil {
		return fmt.Errorf("creating new DID: %w", err)
	}

	newDoc, ok := s.bddContext.PublicDIDDocs[agentID]
	if !ok || myDoc == nil {
		return fmt.Errorf("expected a DID doc to rotate to")
	}

	client := connection.New(agentCtx)

	err = client.RotateDID(connID, authKID, newDoc.ID)
	if err != nil {
		return fmt.Errorf("rotate did: %w", err)
	}

	return nil
}

// createConnection returns the connectionID of the created connection.
func (s *SDKSteps) createConnection(agentCtx *context.Provider, myDID string, target *did.Doc) (string, error) {
	conn := &connection2.Record{
		ConnectionID: uuid.New().String(),
		State:        connection2.StateNameCompleted,
		TheirDID:     target.ID,
		MyDID:        myDID,
		Namespace:    connection2.MyNSPrefix,
	}

	destination, err := service.CreateDestination(target)
	if err != nil {
		return "", fmt.Errorf("createConnection: failed to create destination: %w", err)
	}

	conn.ServiceEndPoint = destination.ServiceEndpoint
	conn.RecipientKeys = destination.RecipientKeys
	conn.RoutingKeys = destination.RoutingKeys

	didConnStore := agentCtx.DIDConnectionStore()

	err = didConnStore.SaveDIDFromDoc(target)
	if err != nil {
		return "", fmt.Errorf("failed to save theirDID to the did.ConnectionStore: %w", err)
	}

	err = didConnStore.SaveDIDByResolving(myDID)
	if err != nil {
		return "", fmt.Errorf("failed to save myDID to the did.ConnectionStore: %w", err)
	}

	connRecorder, err := connection2.NewRecorder(agentCtx)
	if err != nil {
		return "", fmt.Errorf("creating connection recorder: %w", err)
	}

	return conn.ConnectionID, connRecorder.SaveConnectionRecord(conn)
}
