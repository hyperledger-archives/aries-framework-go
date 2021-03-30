/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

func TestNewOverDIDComm(t *testing.T) {
	tests := []struct {
		name    string
		svcName string
		purpose []string
		handle  RequestHandle
		failure string
	}{
		{
			"Successfully create new HTTP Over DIDComm service with all args",
			"sample-name-01",
			[]string{"prp-01", "prp-02"},
			newMockHandle(), "",
		},
		{
			"Successfully create new HTTP Over DIDComm service without purpose",
			"sample-name-01", nil, newMockHandle(), "",
		},
		{
			"Failed to create new HTTP Over DIDComm service without name",
			"",
			[]string{"prp-01", "prp-02"},
			newMockHandle(), errNameAndHandleMandatory,
		},
		{
			"Failed to create new HTTP Over DIDComm service without handle",
			"sample-name-01",
			[]string{"prp-01", "prp-02"},
			nil, errNameAndHandleMandatory,
		},
	}

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			svc, err := NewOverDIDComm(tc.svcName, tc.handle, tc.purpose...)
			if tc.failure != "" {
				require.Error(t, err)
				require.Nil(t, svc)
				require.Contains(t, err.Error(), tc.failure)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, svc)
		})
	}
}

func TestOverDIDComm_Name(t *testing.T) {
	const sampleName = "sample-name-01"

	svc, err := NewOverDIDComm("sample-name-01", newMockHandle(), "prp-01", "prp-02")
	require.NoError(t, err)
	require.NotNil(t, svc)
	require.Equal(t, sampleName, svc.Name())
}

func TestOverDIDComm_Accept(t *testing.T) {
	tests := []struct {
		name      string
		svcName   string
		purpose   []string
		testdatas []struct {
			msgType string
			purpose []string
			result  bool
		}
	}{
		{
			"Test acceptance criteria with purpose",
			"sample-name-01",
			[]string{"foo", "bar"},
			[]struct {
				msgType string
				purpose []string
				result  bool
			}{
				{
					"sample-msgtype-01", []string{"baz"}, false,
				},
				{
					"sample-msgtype-01", []string{""}, false,
				},
				{
					"sample-msgtype-01", nil, false,
				},
				{
					"sample-msgtype-01", []string{"foo"}, false,
				},
				{
					"sample-msgtype-01", []string{"bar"}, false,
				},
				{
					"sample-msgtype-01", []string{"foo", "bar"}, false,
				},
				{
					OverDIDCommMsgRequestType, []string{"bla"}, false,
				},
				{
					OverDIDCommMsgRequestType, []string{}, false,
				},
				{
					OverDIDCommMsgRequestType, nil, false,
				},
				{
					OverDIDCommMsgRequestType, []string{"foo"}, true,
				},
				{
					OverDIDCommMsgRequestType, []string{"bar"}, true,
				},
				{
					OverDIDCommMsgRequestType, []string{"foo", "bar"}, true,
				},
			},
		},
		{
			"Test acceptance criteria without purpose",
			"sample-name-01", nil,
			[]struct {
				msgType string
				purpose []string
				result  bool
			}{
				{
					"sample-msgtype-01", []string{"baz"}, false,
				},
				{
					"sample-msgtype-01", []string{""}, false,
				},
				{
					"sample-msgtype-01", nil, false,
				},
				{
					"sample-msgtype-01", []string{"foo"}, false,
				},
				{
					"sample-msgtype-01", []string{"bar"}, false,
				},
				{
					"sample-msgtype-01", []string{"foo", "bar"}, false,
				},
				{
					OverDIDCommMsgRequestType, []string{"bla"}, true,
				},
				{
					OverDIDCommMsgRequestType, []string{}, true,
				},
				{
					OverDIDCommMsgRequestType, nil, true,
				},
				{
					OverDIDCommMsgRequestType, []string{"foo"}, true,
				},
				{
					OverDIDCommMsgRequestType, []string{"bar"}, true,
				},
				{
					OverDIDCommMsgRequestType, []string{"foo", "bar"}, true,
				},
			},
		},
	}

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			svc, err := NewOverDIDComm(tc.svcName, newMockHandle(), tc.purpose...)
			require.NoError(t, err)
			require.NotNil(t, svc)
			for _, testdata := range tc.testdatas {
				require.Equal(t, testdata.result, svc.Accept(testdata.msgType, testdata.purpose),
					"testdata: %v", testdata)
			}
		})
	}
}

func TestOverDIDComm_HandleInbound(t *testing.T) {
	tests := []struct {
		name     string
		jsonStr  string
		expected struct {
			method      string
			resourceURI string
			body        string
			version     string
			header      []struct {
				key   string
				value string
			}
			failure string
		}
	}{
		{
			name:    "Testing request handle with empty didcomm msg",
			jsonStr: `{"@id":"sample-id", "@type":"https://didcomm.org/http-over-didcomm/1.0/request"}`,
			expected: struct {
				method      string
				resourceURI string
				body        string
				version     string
				header      []struct {
					key   string
					value string
				}
				failure string
			}{
				http.MethodGet, "", "", "HTTP/1.1", nil, "",
			},
		},
		{
			name: "Testing request handle with valid didcomm msg",
			jsonStr: `{"@id":"sample-id", "@type":"https://didcomm.org/http-over-didcomm/1.0/request",
"method":"POST", "resource-uri":"/sample-resource-uri", "headers":[{"name":"header1","value":"value1"}, 
{"name":"header2","value":"value2"}],"body":"eyJjb2RlIjoiMDExMjM0In0="}`,
			expected: struct {
				method      string
				resourceURI string
				body        string
				version     string
				header      []struct {
					key   string
					value string
				}
				failure string
			}{
				http.MethodPost, "/sample-resource-uri", "011234", "HTTP/1.1", []struct {
					key   string
					value string
				}{{"header1", "value1"}, {"header2", "value2"}}, "",
			},
		},
		{
			name:    "Testing failure in handleInBound due to invalid message body",
			jsonStr: `{"@id":"sample-id", "@type":"https://didcomm.org/http-over-didcomm/1.0/request", "body":"--$#@!"}`,
			expected: struct {
				method      string
				resourceURI string
				body        string
				version     string
				header      []struct {
					key   string
					value string
				}
				failure string
			}{
				"", "", "", "", nil, "unable to decode message body",
			},
		},
		{
			name:    "Testing failure in handleInBound due to invalid request fields",
			jsonStr: `{"@id":"sample-id", "@type":"https://didcomm.org/http-over-didcomm/1.0/request", "method":"--$#@!"}`,
			expected: struct {
				method      string
				resourceURI string
				body        string
				version     string
				header      []struct {
					key   string
					value string
				}
				failure string
			}{
				"", "", "", "", nil, "failed to create http request from incoming message",
			},
		},
	}

	rqCh := make(chan *http.Request)

	handle := func(id string, rq *http.Request) error {
		require.Equal(t, "sample-id", id)
		rqCh <- rq

		return nil
	}

	svc, err := NewOverDIDComm("sample-service", handle)
	require.NoError(t, err)
	require.NotNil(t, svc)

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			didCommMsg, err := service.ParseDIDCommMsgMap([]byte(tc.jsonStr))
			require.NoError(t, err)

			if tc.expected.failure != "" {
				_, err = svc.HandleInbound(didCommMsg, service.EmptyDIDCommContext())
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expected.failure)
				return
			}

			go func() {
				_, err = svc.HandleInbound(didCommMsg, service.EmptyDIDCommContext())
				require.NoError(t, err)
			}()

			select {
			case rqst := <-rqCh:
				// test request properties
				require.Equal(t, tc.expected.method, rqst.Method)
				require.Equal(t, tc.expected.version, rqst.Proto)
				require.Equal(t, tc.expected.resourceURI, rqst.URL.String())

				// test body
				if tc.expected.body != "" {
					v := struct {
						Code string `json:"code"`
					}{}

					require.NoError(t, json.NewDecoder(rqst.Body).Decode(&v))
					require.Equal(t, tc.expected.body, v.Code)
				}

				// test headers
				for _, h := range tc.expected.header {
					require.Equal(t, h.value, rqst.Header.Get(h.key))
				}

			case <-time.After(2 * time.Second):
				require.Fail(t, "didn't receive post event responded")
			}
		})
	}
}

func TestOverDIDComm_HandleInbound_InvalidMsg(t *testing.T) {
	svc, err := NewOverDIDComm("sample-service", newMockHandle())
	require.NoError(t, err)
	require.NotNil(t, svc)

	_, err = svc.HandleInbound(&mockMsg{err: fmt.Errorf("sample-error")}, service.EmptyDIDCommContext())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to decode DID comm message")
}

func newMockHandle() RequestHandle {
	return func(string, *http.Request) error { return nil }
}

type mockMsg struct {
	*service.DIDCommMsgMap
	err error
}

func (m *mockMsg) Decode(v interface{}) error {
	return m.err
}
