/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	bddagent "github.com/hyperledger/aries-framework-go/test/bdd/agent"
	bddDIDExchange "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/didresolver"
)

func (s *SDKSteps) createDID(issuer, holder string) error {
	const (
		inboundHost     = "localhost"
		inboundPort     = "random"
		endpointURL     = "${SIDETREE_URL}"
		acceptDidMethod = "sidetree"
	)

	participants := issuer + "," + holder
	agentSDK := bddagent.NewSDKSteps()
	agentSDK.SetContext(s.bddContext)

	err := agentSDK.CreateAgentWithHTTPDIDResolver(participants, inboundHost, inboundPort, endpointURL, acceptDidMethod)
	if err != nil {
		return err
	}

	if err := s.createKeys(participants); err != nil {
		return err
	}

	if err := didresolver.CreateDIDDocument(s.bddContext, participants, "JsonWebKey2020"); err != nil {
		return err
	}

	didExchangeSDK := bddDIDExchange.NewDIDExchangeSDKSteps()
	didExchangeSDK.SetContext(s.bddContext)

	return didExchangeSDK.WaitForPublicDID(participants, 10)
}

func (s *SDKSteps) getPublicDID(agentName string) *did.Doc {
	return s.bddContext.PublicDIDDocs[agentName]
}
