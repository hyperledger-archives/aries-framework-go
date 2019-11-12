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

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didmethod/httpbinding"
	"github.com/hyperledger/aries-framework-go/pkg/didmethod/peer"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

const (
	dbPath = "./db"
)

var logger = log.New("aries-framework/tests")

// AgentSDKSteps contains steps for agent from client SDK
type AgentSDKSteps struct {
	bddContext *context.BDDContext
}

// NewAgentSDKSteps returns new agent from client SDK
func NewAgentSDKSteps(ctx *context.BDDContext) *AgentSDKSteps {
	return &AgentSDKSteps{bddContext: ctx}
}

func (a *AgentSDKSteps) createAgent(agentID, inboundHost, inboundPort string) error {
	var opts []aries.Option

	storeProv, err := a.getStoreProvider(agentID)
	if err != nil {
		return err
	}

	opts = append(opts, aries.WithStoreProvider(storeProv))

	return a.create(agentID, inboundHost, inboundPort, opts...)
}

func (a *AgentSDKSteps) createAgentWithHTTPDIDResolver(
	agentID, inboundHost, inboundPort, endpointURL, acceptDidMethod string) error {
	var opts []aries.Option

	httpResolver, err := httpbinding.New(a.bddContext.Args[endpointURL],
		httpbinding.WithAccept(func(method string) bool { return method == acceptDidMethod }))
	if err != nil {
		return fmt.Errorf("failed from httpbinding new ")
	}

	storeProv, err := a.getStoreProvider(agentID)
	if err != nil {
		return err
	}

	peerDidStore, err := peer.NewDIDStore(storeProv)
	if err != nil {
		return fmt.Errorf("failed to create new did store : %w", err)
	}

	opts = append(opts, aries.WithStoreProvider(storeProv),
		aries.WithDIDResolver(didresolver.New(didresolver.WithDidMethod(httpResolver),
			didresolver.WithDidMethod(peer.NewDIDResolver(peerDidStore)))))

	return a.create(agentID, inboundHost, inboundPort, opts...)
}

func (a *AgentSDKSteps) getStoreProvider(agentID string) (storage.Provider, error) {
	storeProv, err := leveldb.NewProvider(dbPath + "/" + agentID)
	if err != nil {
		return nil, fmt.Errorf("leveldb provider initialization failed : %w", err)
	}

	return storeProv, nil
}

func (a *AgentSDKSteps) create(agentID, inboundHost, inboundPort string, opts ...aries.Option) error {
	if inboundPort == "random" {
		inboundPort = strconv.Itoa(mustGetRandomPort(5))
	}

	inboundAddr := fmt.Sprintf("%s:%s", inboundHost, inboundPort)

	opts = append(opts, defaults.WithInboundHTTPAddr(inboundAddr, "http://"+inboundAddr))

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

	logger.Debugf("Agent %s start listening on %s:%s", agentID, inboundHost, inboundPort)

	return nil
}

// RegisterSteps registers agent steps
func (a *AgentSDKSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)"$`, a.createAgent)
	s.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" `+
		`with http-binding did resolver url "([^"]*)" which accepts did method "([^"]*)"$`, a.createAgentWithHTTPDIDResolver)
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
