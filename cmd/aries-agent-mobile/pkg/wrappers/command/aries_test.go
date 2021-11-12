/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/config"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/didexchange"
)

func TestNewAries(t *testing.T) {
	t.Run("test it creates an instance with a framework and handlers", func(t *testing.T) {
		opts := &config.Options{}
		a, err := NewAries(opts)
		require.NoError(t, err)
		require.NotNil(t, a)

		require.NotNil(t, a.framework)
		require.NotNil(t, a.handlers)
	})
}

type handlerFunc func(topic string, message []byte) error

func (hf handlerFunc) Handle(topic string, message []byte) error {
	return hf(topic, message)
}

func TestAries_RegisterHandler(t *testing.T) {
	const topic = "didexchange_states"

	a, err := NewAries(&config.Options{})
	require.NoError(t, err)
	require.NotNil(t, a)

	done := make(chan struct{})

	defer a.UnregisterHandler(a.RegisterHandler(handlerFunc(func(topic string, message []byte) error {
		if strings.Contains(string(message), "post_state") {
			close(done)

			return nil
		}

		return errors.New("error")
	}), topic))

	ctrl, err := a.GetDIDExchangeController()
	require.NoError(t, err)

	inv := ctrl.CreateInvitation(&models.RequestEnvelope{Payload: []byte(`{}`)})

	var resp *didexchange.CreateInvitationResponse

	require.NoError(t, json.Unmarshal(inv.Payload, &resp))

	src, err := json.Marshal(resp.Invitation)
	require.NoError(t, err)

	ctrl.ReceiveInvitation(&models.RequestEnvelope{Payload: src})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("timeout")
	}
}

func TestAries_GetIntroduceController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		opts := &config.Options{}
		a, err := NewAries(opts)
		require.NoError(t, err)
		require.NotNil(t, a)

		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)
	})
}

func TestAries_GetVerifiableController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		opts := &config.Options{}
		a, err := NewAries(opts)
		require.NoError(t, err)
		require.NotNil(t, a)

		ic, err := a.GetVerifiableController()
		require.NoError(t, err)
		require.NotNil(t, ic)
	})
}

func TestAries_GetDIDExchangeController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		opts := &config.Options{}
		a, err := NewAries(opts)
		require.NoError(t, err)
		require.NotNil(t, a)

		dec, err := a.GetDIDExchangeController()
		require.NoError(t, err)
		require.NotNil(t, dec)
	})
}

func TestAries_GetIssueCredentialController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		opts := &config.Options{}
		a, err := NewAries(opts)
		require.NoError(t, err)
		require.NotNil(t, a)

		ic, err := a.GetIssueCredentialController()
		require.NoError(t, err)
		require.NotNil(t, ic)
	})
}

func TestAries_GetPresentProofController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		opts := &config.Options{}
		a, err := NewAries(opts)
		require.NoError(t, err)
		require.NotNil(t, a)

		p, err := a.GetPresentProofController()
		require.NoError(t, err)
		require.NotNil(t, p)
	})
}

func TestAries_GetVDRController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		opts := &config.Options{}
		a, err := NewAries(opts)
		require.NoError(t, err)
		require.NotNil(t, a)

		v, err := a.GetVDRController()
		require.NoError(t, err)
		require.NotNil(t, v)
	})
}

func TestAries_GetMediatorController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		opts := &config.Options{}
		a, err := NewAries(opts)
		require.NoError(t, err)
		require.NotNil(t, a)

		m, err := a.GetMediatorController()
		require.NoError(t, err)
		require.NotNil(t, m)
	})
}

func TestAries_GetMessagingController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		opts := &config.Options{}
		a, err := NewAries(opts)
		require.NoError(t, err)
		require.NotNil(t, a)

		m, err := a.GetMessagingController()
		require.NoError(t, err)
		require.NotNil(t, m)
	})
}

func TestAries_GetOutOfBandController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		opts := &config.Options{}
		a, err := NewAries(opts)
		require.NoError(t, err)
		require.NotNil(t, a)

		controller, err := a.GetOutOfBandController()
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}

func TestAries_GetKMSController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		opts := &config.Options{}
		a, err := NewAries(opts)
		require.NoError(t, err)
		require.NotNil(t, a)

		controller, err := a.GetKMSController()
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}

func TestAries_GetJSONLDContextController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		opts := &config.Options{}
		a, err := NewAries(opts)
		require.NoError(t, err)
		require.NotNil(t, a)

		controller, err := a.GetLDController()
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}
