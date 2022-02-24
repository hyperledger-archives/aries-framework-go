/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/config"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/kms"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/ld"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest/verifiable"
)

// Aries is an Aries implementation with endpoints to execute operations.
type Aries struct {
	endpoints map[string]map[string]*endpoint

	URL                string
	WebsocketURL       string
	WebsocketReadLimit int64
	Token              string
	mutex              sync.RWMutex
	subscribers        map[string]map[string][]api.Handler
}

// NewAries returns a new Aries instance.
// Use this if you want your requests to be handled by a remote agent.
func NewAries(opts *config.Options) (*Aries, error) {
	if opts == nil || opts.AgentURL == "" {
		return nil, errors.New("no agent url provided")
	}

	endpoints := getControllerEndpoints()

	a := &Aries{
		endpoints:          endpoints,
		URL:                opts.AgentURL,
		Token:              opts.APIToken,
		WebsocketURL:       opts.WebsocketURL,
		WebsocketReadLimit: opts.WebsocketReadLimit,
		subscribers:        make(map[string]map[string][]api.Handler),
	}

	go a.startNotificationListener()

	return a, nil
}

// Incoming represents WebSocket event message.
type Incoming struct {
	ID      string      `json:"id"`
	Topic   string      `json:"topic"`
	Message interface{} `json:"message"`
}

func (ar *Aries) startNotificationListener() {
	if ar.WebsocketURL == "" {
		return
	}

	conn, _, err := websocket.Dial(context.Background(), ar.WebsocketURL, nil) // nolint: bodyclose
	if err != nil {
		logger.Errorf("notification listener: websocket dial: %v", err)

		return
	}

	if ar.WebsocketReadLimit > 0 {
		conn.SetReadLimit(ar.WebsocketReadLimit)
	}

	defer func() {
		err = conn.Close(websocket.StatusNormalClosure, "closing the connection")
		if err != nil && websocket.CloseStatus(err) != websocket.StatusNormalClosure {
			logger.Errorf("notification listener: close connection: %v", err)
		}
	}()

	for {
		var incoming *Incoming
		// listens for notifications
		if err := wsjson.Read(context.Background(), conn, &incoming); err != nil {
			if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
				logger.Errorf("notification listener: read: close connection: %v", err)
			}

			// exit if websocket is closed
			if websocket.CloseStatus(err) != -1 {
				return
			}

			continue
		}

		ar.notifySubscribers(incoming)
	}
}

func (ar *Aries) notifySubscribers(incoming *Incoming) {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	// gets all handlers that were subscribed for the topic
	for _, handlers := range ar.subscribers[incoming.Topic] {
		raw, err := json.Marshal(incoming)
		if err != nil {
			logger.Errorf("notification listener: marshal: %v", err)

			break
		}

		// send the payload to the subscribers
		for _, handler := range handlers {
			if err := handler.Handle(incoming.Topic, raw); err != nil {
				logger.Errorf("notification listener: handle: %v", err)
			}
		}
	}
}

// RegisterHandler registers a handler to process incoming notifications from the framework.
// Handler is implemented by mobile apps.
func (ar *Aries) RegisterHandler(h api.Handler, topics string) string {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()

	id := uuid.New().String()

	for _, topic := range strings.Split(topics, ",") {
		if ar.subscribers[topic] == nil {
			ar.subscribers[topic] = map[string][]api.Handler{}
		}

		ar.subscribers[topic][id] = append(ar.subscribers[topic][id], h)
	}

	return id
}

// UnregisterHandler unregisters a handler by given id.
func (ar *Aries) UnregisterHandler(id string) {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()

	for topic := range ar.subscribers {
		for key := range ar.subscribers[topic] {
			if key == id {
				delete(ar.subscribers[topic], id)
			}
		}
	}
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

// GetVDRController returns a VDR instance.
func (ar *Aries) GetVDRController() (api.VDRController, error) {
	endpoints, ok := ar.endpoints[vdr.VDROperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for controller [%s]", vdr.VDROperationID)
	}

	return &VDR{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
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

// GetLDController returns an LD instance.
func (ar *Aries) GetLDController() (api.LDController, error) {
	endpoints, ok := ar.endpoints[ld.OperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for controller [%s]", ld.OperationID)
	}

	return &LD{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}

// GetVCWalletController returns a VCWalletController instance.
func (ar *Aries) GetVCWalletController() (api.VCWalletController, error) {
	endpoints, ok := ar.endpoints[vcwallet.OperationID]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for controller [%s]", vcwallet.OperationID)
	}

	return &VCWallet{endpoints: endpoints, URL: ar.URL, Token: ar.Token, httpClient: &http.Client{}}, nil
}
