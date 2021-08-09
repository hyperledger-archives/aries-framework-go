/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	ldcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	mockld "github.com/hyperledger/aries-framework-go/pkg/mock/ld"
)

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{}, ldcmd.WithHTTPClient(&mockHTTPClient{}))
		require.NotNil(t, cmd)
	})
}

func TestCommand_GetHandlers(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{})
		require.Equal(t, 6, len(cmd.GetHandlers()))
	})
}

func TestCommand_AddContexts(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{})

		b, err := json.Marshal(ldcmd.AddContextsRequest{Documents: ldtestutil.Contexts()})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.AddContexts(&rw, bytes.NewReader(b))

		require.NoError(t, err)
	})

	t.Run("Fail to decode request", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{})

		var rw bytes.Buffer
		err := cmd.AddContexts(&rw, strings.NewReader("invalid request"))

		require.Error(t, err)
		require.Contains(t, err.Error(), "decode request")
	})

	t.Run("Fail to add contexts", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{ErrAddContexts: errors.New("add contexts error")})

		context := ldtestutil.Contexts()[0]

		b, err := json.Marshal(ldcmd.AddContextsRequest{
			Documents: []ldcontext.Document{
				{
					URL:     context.URL,
					Content: context.Content,
				},
			},
		})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.AddContexts(&rw, bytes.NewReader(b))

		require.Error(t, err)
		require.Contains(t, err.Error(), "add contexts")
	})
}

func TestCommand_AddRemoteProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{})

		b, err := json.Marshal(ldcmd.AddRemoteProviderRequest{Endpoint: "endpoint"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.AddRemoteProvider(&rw, bytes.NewReader(b))

		require.NoError(t, err)
	})

	t.Run("Fail to decode request", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{})

		var rw bytes.Buffer
		err := cmd.AddRemoteProvider(&rw, bytes.NewReader([]byte("invalid request")))

		require.Error(t, err)
		require.Contains(t, err.Error(), "decode request")
	})

	t.Run("Fail to add remote provider", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{ErrAddRemoteProvider: errors.New("add remote provider error")})

		b, err := json.Marshal(ldcmd.AddRemoteProviderRequest{Endpoint: "endpoint"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.AddRemoteProvider(&rw, bytes.NewReader(b))

		require.Error(t, err)
		require.Contains(t, err.Error(), "add remote provider")
	})
}

func TestCommand_RefreshRemoteProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{})

		b, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.RefreshRemoteProvider(&rw, bytes.NewReader(b))

		require.NoError(t, err)
	})

	t.Run("Fail to decode request", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{})

		var rw bytes.Buffer
		err := cmd.RefreshRemoteProvider(&rw, bytes.NewReader([]byte("invalid request")))

		require.Error(t, err)
		require.Contains(t, err.Error(), "decode request")
	})

	t.Run("Fail to refresh remote provider", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{ErrRefreshRemoteProvider: errors.New("refresh provider error")})

		b, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.RefreshRemoteProvider(&rw, bytes.NewReader(b))

		require.Error(t, err)
		require.Contains(t, err.Error(), "refresh remote provider")
	})
}

func TestCommand_DeleteRemoteProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{})

		reqBytes, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.DeleteRemoteProvider(&rw, bytes.NewReader(reqBytes))

		require.NoError(t, err)
	})

	t.Run("Fail to decode request", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{})

		var rw bytes.Buffer
		err := cmd.DeleteRemoteProvider(&rw, bytes.NewReader([]byte("invalid request")))

		require.Error(t, err)
		require.Contains(t, err.Error(), "decode request")
	})

	t.Run("Fail to delete remote provider", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{ErrDeleteRemoteProvider: errors.New("delete provider error")})

		b, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.DeleteRemoteProvider(&rw, bytes.NewReader(b))

		require.Error(t, err)
		require.Contains(t, err.Error(), "delete remote provider")
	})
}

func TestCommand_GetAllRemoteProviders(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{})

		var rw bytes.Buffer
		err := cmd.GetAllRemoteProviders(&rw, bytes.NewReader(nil))

		var resp ldcmd.GetAllRemoteProvidersResponse

		e := json.Unmarshal(rw.Bytes(), &resp)
		require.NoError(t, e)

		require.NoError(t, err)
	})

	t.Run("Fail to get remote providers", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{ErrGetAllRemoteProviders: errors.New("get providers error")})

		var rw bytes.Buffer
		err := cmd.GetAllRemoteProviders(&rw, bytes.NewReader(nil))

		require.Error(t, err)
		require.Contains(t, err.Error(), "get remote providers")
	})
}

func TestCommand_RefreshAllRemoteProviders(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{})

		var rw bytes.Buffer
		err := cmd.RefreshAllRemoteProviders(&rw, bytes.NewReader(nil))

		require.NoError(t, err)
	})

	t.Run("Fail to refresh remote providers", func(t *testing.T) {
		cmd := ldcmd.New(&mockld.MockService{ErrRefreshAllRemoteProviders: errors.New("refresh providers error")})

		var rw bytes.Buffer
		err := cmd.RefreshAllRemoteProviders(&rw, bytes.NewReader(nil))

		require.Error(t, err)
		require.Contains(t, err.Error(), "refresh remote providers")
	})
}

type mockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}
