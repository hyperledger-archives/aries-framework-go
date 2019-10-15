/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/envelope"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/envelope"
)

type mockProvider struct {
	packagerValue envelope.Packager
}

func (p *mockProvider) InboundMessageHandler() transport.InboundMessageHandler {
	return func(message []byte) error {
		logger.Debugf("message received is %s", message)
		return nil
	}
}

func (p *mockProvider) Packager() envelope.Packager {
	return p.packagerValue
}

func TestInboundHandler(t *testing.T) {
	// test inboundHandler with empty args should fail
	inHandler, err := NewInboundHandler(nil)
	require.Error(t, err)
	require.Nil(t, inHandler)
	mockPackager := &mockpackager.BasePackager{UnpackValue: &envelope.Envelope{Message: []byte("data")}}
	// now create a valid inboundHandler to continue testing..
	inHandler, err = NewInboundHandler(&mockProvider{packagerValue: mockPackager})

	require.NoError(t, err)
	require.NotNil(t, inHandler)
	server := startMockServer(inHandler)
	port := getServerPort(server)
	serverURL := fmt.Sprintf("https://localhost:%d", port)
	defer func() {
		e := server.Close()
		if e != nil {
			t.Fatalf("Failed to stop server: %s", e)
		}
	}()

	// build a mock cert pool
	cp := x509.NewCertPool()
	err = addCertsToCertPool(cp)
	require.NoError(t, err)

	// build a tls.Config instance to be used by the outbound transport
	tlsConfig := &tls.Config{
		RootCAs:      cp,
		Certificates: nil,
	}

	// create an http client to communicate with the server that has our inbound handlers set above
	client := http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// test http.Get should should fail (not supported)
	rs, err := client.Get(serverURL + "/")
	require.NoError(t, err)
	err = rs.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusMethodNotAllowed, rs.StatusCode)

	// test accepted HTTP method (POST) but with bad content type
	rs, err = client.Post(serverURL+"/", "bad-content-type", bytes.NewBuffer([]byte("Hello World")))
	require.NoError(t, err)
	err = rs.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusUnsupportedMediaType, rs.StatusCode)

	// test with nil body ..
	rs, err = client.Post(serverURL+"/", commContentType, nil)
	require.NoError(t, err)
	err = rs.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, rs.StatusCode)

	// finally test successful POST requests
	data := "success"

	resp, err := client.Post(serverURL+"/", commContentType, bytes.NewBuffer([]byte(data)))
	require.NoError(t, err)
	err = resp.Body.Close()
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	// test unpack error
	mockPackager.UnpackValue = nil
	mockPackager.UnpackErr = fmt.Errorf("unpack error")
	resp, err = client.Post(serverURL+"/", commContentType, bytes.NewBuffer([]byte(data)))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "failed to unpack msg")
	require.NoError(t, resp.Body.Close())
}

func TestInboundTransport(t *testing.T) {
	t.Run("test inbound transport - with host/port", func(t *testing.T) {
		inbound, err := NewInbound("example.com:26601")
		require.NoError(t, err)
		require.Equal(t, "http://example.com:26601", inbound.Endpoint())
	})

	t.Run("test inbound transport - without host/port", func(t *testing.T) {
		inbound, err := NewInbound(":26602")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)
		mockPackager := &mockpackager.BasePackager{UnpackValue: &envelope.Envelope{Message: []byte("data")}}
		err = inbound.Start(&mockProvider{packagerValue: mockPackager})
		require.NoError(t, err)

		err = inbound.Stop()
		require.NoError(t, err)
	})

	t.Run("test inbound transport - nil context", func(t *testing.T) {
		inbound, err := NewInbound(":26603")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		err = inbound.Start(nil)
		require.Error(t, err)
	})

	t.Run("test inbound transport - invalid port number", func(t *testing.T) {
		_, err := NewInbound("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "http address is mandatory")
	})

	t.Run("test inbound transport - invoke endpoint", func(t *testing.T) {
		// initiate inbound with port
		inbound, err := NewInbound(":26604")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		// start server
		mockPackager := &mockpackager.BasePackager{UnpackValue: &envelope.Envelope{Message: []byte("data")}}
		err = inbound.Start(&mockProvider{packagerValue: mockPackager})
		require.NoError(t, err)
		require.NoError(t, listenFor("localhost:26604", time.Second))
		// invoke a endpoint
		client := http.Client{}
		resp, err := client.Post("http://localhost:26604", commContentType, bytes.NewBuffer([]byte("success")))
		require.NoError(t, err)
		require.Equal(t, http.StatusAccepted, resp.StatusCode)
		require.NotNil(t, resp)

		err = resp.Body.Close()
		require.NoError(t, err)

		// stop server
		err = inbound.Stop()
		require.NoError(t, err)

		// try after server stop
		_, err = client.Post("http://localhost:26604", commContentType, bytes.NewBuffer([]byte("success"))) // nolint
		require.Error(t, err)
	})
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
