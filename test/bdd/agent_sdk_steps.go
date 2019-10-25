/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/DATA-DOG/godog"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didmethod/httpbinding"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
)

const (
	dbPath = "./db"
)

var logger = log.New("aries-framework/tests")

// AgentSDKSteps
type AgentSDKSteps struct {
	bddContext *Context
}

// NewAgentSDKSteps
func NewAgentSDKSteps(context *Context) *AgentSDKSteps {
	return &AgentSDKSteps{bddContext: context}
}

func (a *AgentSDKSteps) createAgent(agentID, inboundHost, inboundPort string) error {
	return a.create(agentID, inboundHost, inboundPort)
}

func (a *AgentSDKSteps) createAgentWithHttpDIDResolver(agentID, inboundHost, inboundPort, endpointURL, acceptDidMethod string) error {
	var opts []aries.Option
	httpResolver, err := httpbinding.New(a.bddContext.Args[endpointURL],
		httpbinding.WithAccept(func(method string) bool { return method == acceptDidMethod }))
	if err != nil {
		return fmt.Errorf("failed from httpbinding new ")
	}
	opts = append(opts, aries.WithDIDResolver(didresolver.New(didresolver.WithDidMethod(httpResolver))))
	return a.create(agentID, inboundHost, inboundPort, opts...)
}

func (a *AgentSDKSteps) create(agentID, inboundHost, inboundPort string, opts ...aries.Option) error {
	if inboundPort == "random" {
		inboundPort = strconv.Itoa(mustGetRandomPort(5))
	}
	opts = append(opts, defaults.WithInboundHTTPAddr(fmt.Sprintf("%s:%s", inboundHost, inboundPort)))
	opts = append(opts, defaults.WithStorePath(dbPath+"/"+agentID))
	agent, err := aries.New(opts...)
	if err != nil {
		return fmt.Errorf("failed to create new agent: %w", err)
	}
	ctx, err := agent.Context()
	if err != nil {
		return fmt.Errorf("failed to create context: %w", err)
	}
	a.bddContext.AgentCtx[agentID] = ctx
	if err := listenFor(fmt.Sprintf("%s:%s", inboundHost, inboundPort), 2*time.Second); err != nil {
		return err
	}

	logger.Infof("Agent %s start listening on %s:%s", agentID, inboundHost, inboundPort)
	return nil
}

func (a *AgentSDKSteps) createDIDExchangeClient(agentID string) error {

	// create new did exchange client
	didexchangeClient, err := didexchange.New(a.bddContext.AgentCtx[agentID])
	if err != nil {
		return fmt.Errorf("failed to create new didexchange client: %w", err)
	}

	actionCh := make(chan service.DIDCommAction)
	err = didexchangeClient.RegisterActionEvent(actionCh)
	go func() {
		if err := service.AutoExecuteActionEvent(actionCh); err != nil {
			panic(err)
		}
	}()

	a.bddContext.DIDExchangeClients[agentID] = didexchangeClient
	return nil
}

func closeResponse(c io.Closer) {
	err := c.Close()
	if err != nil {
		logger.Errorf("Failed to close response body : %s", err)
	}
}

func (a *AgentSDKSteps) registerPostMsgEvent(agentID, statesValue string) error {
	statusCh := make(chan service.StateMsg, 1)
	if err := a.bddContext.DIDExchangeClients[agentID].RegisterMsgEvent(statusCh); err != nil {
		return fmt.Errorf("failed to register msg event: %w", err)
	}
	states := strings.Split(statesValue, ",")
	a.initializeStates(agentID, states)

	go a.eventListener(statusCh, agentID, states)

	return nil
}

func (a *AgentSDKSteps) initializeStates(agentID string, states []string) {
	a.bddContext.PostStatesFlag[agentID] = make(map[string]chan bool)
	for _, state := range states {
		a.bddContext.PostStatesFlag[agentID][state] = make(chan bool)
	}
}

// RegisterSteps registers agent steps
func (a *AgentSDKSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)"$`, a.createAgent)
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" with http-binding did resolver url "([^"]*)" which accepts did method "([^"]*)"$`,
		a.createAgentWithHttpDIDResolver)
	s.Step(`^"([^"]*)" creates did exchange client$`, a.createDIDExchangeClient)
	s.Step(`^"([^"]*)" registers to receive notification for post state event "([^"]*)"$`, a.registerPostMsgEvent)
}

func mustGetRandomPort(n int) int {
	for ; n > 0; n-- {
		port, err := getRandomPort()
		if err != nil {
			continue
		}
		return port
	}
	panic("cannot acquire the random port")
}

func getRandomPort() (int, error) {
	const network = "tcp"
	addr, err := net.ResolveTCPAddr(network, "localhost:0")
	if err != nil {
		return 0, err
	}
	listener, err := net.ListenTCP(network, addr)
	if err != nil {
		return 0, err
	}
	if err := listener.Close(); err != nil {
		return 0, err
	}
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func listenFor(host string, d time.Duration) error {
	timeout := time.After(d)
	for {
		select {
		case <-timeout:
			return errors.New("timeout: server is not available")
		default:
			conn, err := net.Dial("tcp", host)
			if err != nil {
				continue
			}
			return conn.Close()
		}
	}
}

func (a *AgentSDKSteps) eventListener(statusCh chan service.StateMsg, agentID string, states []string) {
	var props didexchange.Event
	for e := range statusCh {
		switch v := e.Properties.(type) {
		case didexchange.Event:
			props = v
		case error:
			panic(fmt.Sprintf("Service processing failed: %s", v))
		}

		a.bddContext.ConnectionID[agentID] = props.ConnectionID()
		if e.Type == service.PostState {
			for _, state := range states {
				// receive the events
				if e.StateID == state {
					a.bddContext.PostStatesFlag[agentID][state] <- true
				}

			}
		}
	}
}
