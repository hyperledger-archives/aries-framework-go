/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/internal/test/transportutil"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/packager"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
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
			UnpackValue: &transport.Envelope{Message: request, FromKey: verKeyBytes},
		}

		response := "Hello"
		transportProvider := &mockTransportProvider{
			packagerValue: mockPackager,
			frameworkID:   uuid.New().String(),
			executeInbound: func(envelope *transport.Envelope) error {
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
			executeInbound: func(envelope *transport.Envelope) error {
				// validate the echo server response with the outbound sent message
				require.Equal(t, request, envelope.Message)
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

func TestCheckKeyAgreementIDs(t *testing.T) {
	t.Run("fail: didcomm v1", func(t *testing.T) {
		tests := []struct {
			name string
			data string
			err  string
		}{
			{
				name: "unmarshal message",
				data: "not json",
				err:  "unmarshal request message failed",
			},
			{
				name: "no attachment",
				data: `{}`,
				err:  "fetch message attachment/attachmentData is empty",
			},
			{
				name: "attachment error",
				data: `{"did_doc~attach":{}}`,
				err:  "fetch message attachment data failed",
			},
			{
				name: "unmarshal did doc",
				data: `{"did_doc~attach":{"data":{"base64":"bm90IGpzb24="}}}`,
				err:  "unmarshal DID doc from attachment data failed",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				_, err := didCommV1PeerDoc([]byte(tc.data))
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.err)
			})
		}
	})

	t.Run("fail: didcomm v2", func(t *testing.T) {
		tests := []struct {
			name string
			data string
			err  string
		}{
			{
				name: "unmarshal message",
				data: "not json",
				err:  "unmarshal message as didcomm/v2 failed",
			},
			{
				name: "no 'from' field",
				data: `{}`,
				err:  "message has no didcomm/v2 'from' field",
			},
			{
				name: "'from' field not DID URL",
				data: `{"from":"aaaaa"}`,
				err:  "'from' field not did url",
			},
			{
				name: "'from' DID not peer DID",
				data: `{"from":"did:foo:bar"}`,
				err:  "'from' DID not peer DID",
			},
			{
				name: "DID has no initialState",
				data: `{"from":"did:peer:foo"}`,
				err:  "peer DID URL has no initialState parameter",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				_, err := didCommV2PeerDoc([]byte(tc.data))
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.err)
			})
		}
	})

	t.Run("success: didcomm v1", func(t *testing.T) {
		doc := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "foo")

		req := &didexchange.Request{
			DocAttach: &decorator.Attachment{
				Data: decorator.AttachmentData{
					JSON: doc,
				},
			},
		}

		msg, err := json.Marshal(req)
		require.NoError(t, err)

		_, err = didCommV1PeerDoc(msg)
		require.NoError(t, err)

		ids := checkKeyAgreementIDs(msg)
		require.Len(t, ids, 1)
	})

	t.Run("success: didcomm v2", func(t *testing.T) {
		doc := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "foo")

		initialState, err := peer.UnsignedGenesisDelta(doc)
		require.NoError(t, err)

		msg := fmt.Sprintf(`{"from":"%s?initialState=%s"}`, doc.ID, initialState)

		_, err = didCommV2PeerDoc([]byte(msg))
		require.NoError(t, err)

		ids := checkKeyAgreementIDs([]byte(msg))
		require.Len(t, ids, 1)
	})
}
