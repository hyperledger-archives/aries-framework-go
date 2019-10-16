/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/DATA-DOG/godog"
	"github.com/sirupsen/logrus"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	didexsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
)

const (
	dbPath = "./db"
)

var logger = logrus.New()

// AgentSteps
type AgentSteps struct {
	bddContext *Context
}

// NewAgentSteps
func NewAgentSteps(context *Context) *AgentSteps {
	return &AgentSteps{bddContext: context}
}

func (a *AgentSteps) createAgent(agentID, inboundHost, inboundPort string) error {
	if inboundPort == "random" {
		inboundPort = strconv.Itoa(mustGetRandomPort(5))
	}
	agent, err := aries.New(defaults.WithInboundHTTPAddr(fmt.Sprintf("%s:%s", inboundHost, inboundPort)), defaults.WithStorePath(dbPath+"/"+agentID))
	if err != nil {
		return fmt.Errorf("failed to create new agent: %w", err)
	}
	ctx, err := agent.Context()
	if err != nil {
		return fmt.Errorf("failed to create context: %w", err)
	}
	// create new did exchange client
	didexchangeClient, err := didexchange.New(ctx)
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

	if err := listenFor(fmt.Sprintf("%s:%s", inboundHost, inboundPort), 2*time.Second); err != nil {
		return err
	}

	logger.Infof("Agent %s start listening on %s:%s", agentID, inboundHost, inboundPort)
	return nil

}

func (a *AgentSteps) registerPostMsgEvent(agentID, statesValue string) error {
	statusCh := make(chan service.StateMsg, 1)
	if err := a.bddContext.DIDExchangeClients[agentID].RegisterMsgEvent(statusCh); err != nil {
		return fmt.Errorf("failed to register msg event: %w", err)
	}
	states := strings.Split(statesValue, ",")
	a.initializeStates(agentID, states)

	go a.eventListener(statusCh, agentID, states)

	return nil
}

func (a *AgentSteps) initializeStates(agentID string, states []string) {
	a.bddContext.PostStatesFlag[agentID] = make(map[string]chan bool)
	for _, state := range states {
		a.bddContext.PostStatesFlag[agentID][state] = make(chan bool)
	}
}

// RegisterSteps registers agent steps
func (a *AgentSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)"$`, a.createAgent)
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

func (a *AgentSteps) eventListener(statusCh chan service.StateMsg, agentID string, states []string) {
	var props didexsvc.Event
	for e := range statusCh {
		switch v := e.Properties.(type) {
		case didexsvc.Event:
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
