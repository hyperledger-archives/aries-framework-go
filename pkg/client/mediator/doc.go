/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package mediator enables the agent to register with the router. Once the agent is registered,
// the Router is responsible for routing/forwarding the DIDComm messages to the agent. During
// router registration, the agent receives routers service endpoint and routing keys. These
// details are used in DID Exchange Invitation or DID Document Service Descriptor.
package mediator
