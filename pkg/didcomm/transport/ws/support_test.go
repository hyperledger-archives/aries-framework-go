/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	commontransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/internal/test/transportutil"
)

type mockProvider struct {
	packagerValue commontransport.Packager
}

func (p *mockProvider) InboundMessageHandler() transport.InboundMessageHandler {
	return func(message []byte, myDID, theirDID string) error {
		logger.Infof("message received is %s", string(message))

		if string(message) == "invalid-data" {
			return errors.New("error")
		}

		return nil
	}
}

func (p *mockProvider) Packager() commontransport.Packager {
	return p.packagerValue
}

func (p *mockProvider) AriesFrameworkID() string {
	return uuid.New().String()
}

func websocketClient(t *testing.T, port string) (*websocket.Conn, func()) {
	require.NoError(t, transportutil.VerifyListener("localhost"+port, time.Second))

	u := url.URL{Scheme: "ws", Host: "localhost" + port, Path: ""}
	c, resp, err := websocket.Dial(context.Background(), u.String(), nil) //nolint:bodyclose (library closes the body)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	return c, func() {
		require.NoError(t, c.Close(websocket.StatusNormalClosure, "closing the connection"))
	}
}

func prepareDestination(endPoint string) *service.Destination {
	return &service.Destination{
		ServiceEndpoint: endPoint,
	}
}

func prepareDestinationWithTransport(endPoint, returnRoute string, recipientKeys []string) *service.Destination {
	return &service.Destination{
		ServiceEndpoint:      endPoint,
		RecipientKeys:        recipientKeys,
		TransportReturnRoute: returnRoute,
	}
}

func createTransportDecRequest(t *testing.T, transportReturnRoute string) []byte {
	req := &decorator.Thread{
		ID: uuid.New().String(),
	}

	outboundReq := struct {
		*decorator.Transport
		*decorator.Thread
	}{
		&decorator.Transport{ReturnRoute: &decorator.ReturnRoute{Value: transportReturnRoute}},
		req,
	}
	request, err := json.Marshal(outboundReq)
	require.NoError(t, err)
	require.NotNil(t, request)

	return request
}

func startWebSocketServer(t *testing.T, handlerFunc func(*testing.T, http.ResponseWriter, *http.Request)) string {
	addr := "localhost:" + strconv.Itoa(transportutil.GetRandomPort(5))

	server := &http.Server{Addr: addr}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerFunc(t, w, r)
	})

	go func() {
		require.NoError(t, server.ListenAndServe())
	}()

	require.NoError(t, transportutil.VerifyListener(addr, time.Second))

	return addr
}

func echo(t *testing.T, w http.ResponseWriter, r *http.Request) {
	c, err := Accept(w, r)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, c.Close(websocket.StatusNormalClosure, "closing the connection"))
	}()

	ctx := context.Background()

	for {
		mt, message, err := c.Read(ctx)
		if err != nil {
			break
		}

		logger.Infof("r: %s", message)

		err = c.Write(ctx, mt, message)
		require.NoError(t, err)
	}
}

// mockPackager mock packager.
type mockPackager struct {
	verKey string
}

func (m *mockPackager) PackMessage(e *commontransport.Envelope) ([]byte, error) {
	return e.Message, nil
}

func (m *mockPackager) UnpackMessage(encMessage []byte) (*commontransport.Envelope, error) {
	return &commontransport.Envelope{Message: encMessage, FromKey: base58.Decode(m.verKey)}, nil
}

type mockTransportProvider struct {
	packagerValue  commontransport.Packager
	executeInbound func(message []byte, myDID, theirDID string) error
	frameworkID    string
}

func (p *mockTransportProvider) InboundMessageHandler() transport.InboundMessageHandler {
	return p.executeInbound
}

func (p *mockTransportProvider) Packager() commontransport.Packager {
	return p.packagerValue
}

func (p *mockTransportProvider) AriesFrameworkID() string {
	if p.frameworkID != "" {
		return p.frameworkID
	}

	return "framework-instance-1"
}
