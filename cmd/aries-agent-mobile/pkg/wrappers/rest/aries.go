/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/config"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/kms"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/verifiable"
)

// Aries is an Aries implementation with endpoints to execute operations.
type Aries struct {
	endpoints map[string]map[string]*endpoint
	notifiers map[string]api.Notifier

	URL   string
	Token string
}

// NewAries returns a new Aries instance.
// Use this if you want your requests to be handled by a remote agent.
func NewAries(opts *config.Options) (*Aries, error) {
	if opts == nil || opts.AgentURL == "" {
		return nil, errors.New("no agent url provided")
	}

	endpoints := getControllerEndpoints()

	return &Aries{endpoints: endpoints, URL: opts.AgentURL, Token: opts.APIToken}, nil
}

// RegisterNotifier associates a notifier to relevant topics.
// This is implemented by mobile apps and uses WebSockets.
func (ar *Aries) RegisterNotifier(n api.Notifier, topics string) error {
	/* ... */

	for _, topic := range strings.Split(topics, ",") {
		ar.notifiers[topic] = n
		if err := n.Notify(topic, n.GetPayload()); err != nil {
			return fmt.Errorf("failed to register notifier to topic [%s]: %w", topic, err)
		}
	}

	/* ... */

	return nil
}

// GetIntroduceController returns an Introduce instance.
func (ar *Aries) GetIntroduceController() (api.IntroduceController, error) {
	endpoints, ok := ar.endpoints[introduce.OperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for controller [%s]", introduce.OperationID)
	}

	return &Introduce{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}

// GetVerifiableController returns an Verifiable instance.
func (ar *Aries) GetVerifiableController() (api.VerifiableController, error) {
	endpoints, ok := ar.endpoints[verifiable.VerifiableOperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for controller [%s]", verifiable.VerifiableOperationID)
	}

	return &Verifiable{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}

// GetDIDExchangeController returns a DIDExchange instance.
func (ar *Aries) GetDIDExchangeController() (api.DIDExchangeController, error) {
	endpoints, ok := ar.endpoints[didexchange.OperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for controller [%s]", didexchange.OperationID)
	}

	return &DIDExchange{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}

// GetIssueCredentialController returns an IssueCredential instance.
func (ar *Aries) GetIssueCredentialController() (api.IssueCredentialController, error) {
	endpoints, ok := ar.endpoints[issuecredential.OperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for controller [%s]", issuecredential.OperationID)
	}

	return &IssueCredential{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}

// GetPresentProofController returns a PresentProof instance.
func (ar *Aries) GetPresentProofController() (api.PresentProofController, error) {
	endpoints, ok := ar.endpoints[presentproof.OperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for controller [%s]", presentproof.OperationID)
	}

	return &PresentProof{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}

// GetVDRIController returns a VDRI instance.
func (ar *Aries) GetVDRIController() (api.VDRIController, error) {
	endpoints, ok := ar.endpoints[vdri.VdriOperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for controller [%s]", vdri.VdriOperationID)
	}

	return &VDRI{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}

// GetMediatorController returns a Mediator instance.
func (ar *Aries) GetMediatorController() (api.MediatorController, error) {
	endpoints, ok := ar.endpoints[mediator.RouteOperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for controller [%s]", mediator.RouteOperationID)
	}

	return &Mediator{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}

// GetMessagingController returns a Messaging instance.
func (ar *Aries) GetMessagingController() (api.MessagingController, error) {
	endpoints, ok := ar.endpoints[messaging.MsgServiceOperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for controller [%s]", messaging.MsgServiceOperationID)
	}

	return &Messaging{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}

// GetOutOfBandController returns a OutOfBand instance.
func (ar *Aries) GetOutOfBandController() (api.OutOfBandController, error) {
	endpoints, ok := ar.endpoints[outofband.OperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for controller [%s]", outofband.OperationID)
	}

	return &OutOfBand{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}

// GetKMSController returns a KMS instance.
func (ar *Aries) GetKMSController() (api.KMSController, error) {
	endpoints, ok := ar.endpoints[kms.KmsOperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for controller [%s]", kms.KmsOperationID)
	}

	return &KMS{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}
