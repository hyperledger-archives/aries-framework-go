/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	jsonldcontext "github.com/hyperledger/aries-framework-go/pkg/client/jsonld/context"
	"github.com/hyperledger/aries-framework-go/pkg/internal/jsonldtest"
)

func TestClient_Add(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader(nil)),
				}, nil
			},
		}

		client := jsonldcontext.NewClient("", jsonldcontext.WithHTTPClient(httpClient))
		require.NotNil(t, client)

		err := client.Add(context.Background(), jsonldtest.Contexts()...)
		require.NoError(t, err)
	})

	t.Run("Fail to make HTTP request", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("error making HTTP request")
			},
		}

		client := jsonldcontext.NewClient("", jsonldcontext.WithHTTPClient(httpClient))
		require.NotNil(t, client)

		err := client.Add(context.Background(), jsonldtest.Contexts()...)
		require.Error(t, err)
		require.Contains(t, err.Error(), "http do: error making HTTP request")
	})

	t.Run("Receive error response", func(t *testing.T) {
		respBody, err := json.Marshal(struct {
			Message string `json:"message"`
		}{
			Message: "error response",
		})
		require.NoError(t, err)

		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       ioutil.NopCloser(bytes.NewReader(respBody)),
				}, nil
			},
		}

		client := jsonldcontext.NewClient("", jsonldcontext.WithHTTPClient(httpClient))
		require.NotNil(t, client)

		err = client.Add(context.Background(), jsonldtest.Contexts()...)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error response")
	})
}

type mockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}
