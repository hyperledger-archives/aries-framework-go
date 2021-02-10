/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"

	commontransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/internal/test/transportutil"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/packager"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

func TestConnectionStore(t *testing.T) {
	t.Run("test transport pool - agent with inbound (consumer)", func(t *testing.T) {
		// request to be sent to the framework (with route option)
		request := createTransportDecRequest(t, decorator.TransportReturnRouteAll)

		// ------- setup the framework - with inbound transport ----- //
		// instantiate inbound with port
		port := ":" + strconv.Itoa(transportutil.GetRandomPort(5))
		inbound, err := NewInbound(port, "", "", "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		// instantiate outbound
		outbound := NewOutbound()
		require.NotNil(t, outbound)

		// create a transport provider (framework context)
		verKey := mockdiddoc.MockDIDKey(t)

		verKeyBytes, err := fingerprint.PubKeyFromDIDKey(verKey)
		require.NoError(t, err)

		mockPackager := &mockpackager.Packager{
			UnpackValue: &commontransport.Envelope{Message: request, FromKey: verKeyBytes},
		}

		response := "Hello"
		transportProvider := &mockTransportProvider{
			packagerValue: mockPackager,
			frameworkID:   uuid.New().String(),
			executeInbound: func(message []byte, myDID, theirDID string) error {
				resp, outboundErr := outbound.Send([]byte(response),
					prepareDestinationWithTransport("ws://doesnt-matter", "", []string{verKey}))
				require.NoError(t, outboundErr)
				require.Equal(t, "", resp)
				return nil
			},
		}

		// start inbound
		err = inbound.Start(transportProvider)
		require.NoError(t, err)

		// start outbound
		err = outbound.Start(transportProvider)
		require.NoError(t, err)
		// ------- framework setup complete ----- //

		// Consumer of the framework (fetches and receives message in same websocket client)
		client, cleanup := websocketClient(t, port)
		defer cleanup()

		ctx := context.Background()

		err = client.Write(ctx, websocket.MessageText, request)
		require.NoError(t, err)

		mt, message, err := client.Read(ctx)
		require.NoError(t, err)
		require.Equal(t, websocket.MessageText, mt)
		require.Equal(t, response, string(message))
	})

	t.Run("test transport pool - agent without inbound (client)", func(t *testing.T) {
		// request to be sent to the framework (with route option)
		request := createTransportDecRequest(t, decorator.TransportReturnRouteAll)

		// agent with inbound - just echoes messages back
		addr := startWebSocketServer(t, echo)

		// ------- setup the framework : without inbound transport ----- //
		// instantiate outbound
		outbound := NewOutbound()
		require.NotNil(t, outbound)

		// create a transport provider (framework context)
		verKey := "ABCD"

		done := make(chan struct{})

		transportProvider := &mockTransportProvider{
			packagerValue: &mockPackager{verKey: verKey},
			frameworkID:   uuid.New().String(),
			executeInbound: func(message []byte, myDID, theirDID string) error {
				// validate the echo server response with the outbound sent message
				require.Equal(t, request, message)
				done <- struct{}{}
				return nil
			},
		}

		// start outbound
		err := outbound.Start(transportProvider)
		require.NoError(t, err)
		// ------- framework setup complete ----- //

		// send the outbound message
		resp, err := outbound.Send(request,
			prepareDestinationWithTransport("ws://"+addr, decorator.TransportReturnRouteAll, []string{verKey}))
		require.NoError(t, err)
		require.Equal(t, "", resp)

		// make sure response is received by the agent
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, "tests are not validated due to timeout")
		}
	})
}
