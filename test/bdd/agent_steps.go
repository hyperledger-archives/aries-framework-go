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
	"time"

	"github.com/DATA-DOG/godog"
	"github.com/sirupsen/logrus"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
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

	// TODO https://github.com/hyperledger/aries-framework-go/issues/394 handle client events
	actionCh := make(chan dispatcher.DIDCommAction)
	err = didexchangeClient.RegisterActionEvent(actionCh)
	go didexchange.AutoExecuteActionEvent(actionCh)

	a.bddContext.DIDExchangeClients[agentID] = didexchangeClient

	if err := listenFor(fmt.Sprintf("%s:%s", inboundHost, inboundPort), 2*time.Second); err != nil {
		return err
	}

	logger.Infof("Agent %s start listening on %s:%s", agentID, inboundHost, inboundPort)
	return nil

}

// RegisterSteps registers agent steps
func (a *AgentSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)"$`, a.createAgent)
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
			if err := conn.Close(); err != nil {
				return err
			}
			return nil
		}
	}
}
