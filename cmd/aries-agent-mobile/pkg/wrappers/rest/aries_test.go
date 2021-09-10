/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/config"
)

func TestNewAries(t *testing.T) {
	t.Run("test it creates a rest agent instance with endpoints", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)
		require.NotNil(t, a.endpoints)
		require.GreaterOrEqual(t, len(a.endpoints), 1)
	})
}

func TestAries_GetIntroduceController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)
	})
}

type handlerFunc func(topic string, message []byte) error

func (hf handlerFunc) Handle(topic string, message []byte) error {
	return hf(topic, message)
}

type wsFunc func(w http.ResponseWriter, r *http.Request)

func (wf wsFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wf(w, r)
}

func TestAries_RegisterHandler(t *testing.T) {
	const topic = "didexchange_states"

	done := make(chan struct{})

	s := &http.Server{Handler: wsFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			c   *websocket.Conn
			err error
		)

		c, err = websocket.Accept(w, r, &websocket.AcceptOptions{})
		require.NoError(t, err)

		defer func() {
			require.NoError(t, c.Close(websocket.StatusNormalClosure, "closed"))
		}()

		require.NoError(t, c.Write(context.Background(), websocket.MessageText, []byte(
			`{"topic":"`+topic+`", "message":{"state":"pre_state"}}`,
		)))

		require.NoError(t, c.Write(context.Background(), websocket.MessageText, []byte(
			`{"topic":"`+topic+`", "message":{"state":"post_state"}}`,
		)))

		<-done
	})}

	closed := make(chan struct{})

	l, err := net.Listen("tcp", ":0") // nolint: gosec
	require.NoError(t, err)

	wsURL := strings.Replace(fmt.Sprintf("ws://%v", l.Addr()), "[::]", "localhost", 1)

	go func() {
		require.EqualError(t, s.Serve(l), "http: Server closed")

		close(closed)
	}()

	defer func() {
		require.NoError(t, s.Close())

		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Error("timeout waiting for server to be closed")
		}
	}()

	a, err := NewAries(&config.Options{
		AgentURL:     mockAgentURL,
		WebsocketURL: wsURL,
	})
	require.NoError(t, err)
	require.NotNil(t, a)

	defer a.UnregisterHandler(a.RegisterHandler(handlerFunc(func(topic string, message []byte) error {
		if strings.Contains(string(message), "post_state") {
			close(done)

			return nil
		}

		return errors.New("error")
	}), topic))

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("timeout")
	}
}

func TestAries_GetVerifiableController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		ic, err := a.GetVerifiableController()
		require.NoError(t, err)
		require.NotNil(t, ic)
	})
}

func TestAries_GetDIDExchangeController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		de, err := a.GetDIDExchangeController()
		require.NoError(t, err)
		require.NotNil(t, de)
	})
}

func TestAries_GetIssueCredentialController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		ic, err := a.GetIssueCredentialController()
		require.NoError(t, err)
		require.NotNil(t, ic)
	})
}

func TestAries_GetPresentProofController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		controller, err := a.GetPresentProofController()
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}

func TestAries_GetVDRController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		controller, err := a.GetVDRController()
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}

func TestAries_GetMediatorController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		controller, err := a.GetMediatorController()
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}

func TestAries_GetMessagingController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		controller, err := a.GetMessagingController()
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}

func TestAries_GetOutOfBandController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		controller, err := a.GetOutOfBandController()
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}

func TestAries_GetKMSController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		controller, err := a.GetKMSController()
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}
