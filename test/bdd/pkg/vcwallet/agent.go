/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	bddagent "github.com/hyperledger/aries-framework-go/test/bdd/agent"
)

func (s *SDKSteps) createAgent(agent, inboundHost, inboundPort, endpointURL, acceptDidMethod string) error {
	agentSDK := bddagent.NewSDKSteps()
	agentSDK.SetContext(s.bddContext)

	return agentSDK.CreateAgentWithHTTPDIDResolver(
		agent,
		inboundHost,
		inboundPort,
		endpointURL,
		acceptDidMethod,
	)
}
