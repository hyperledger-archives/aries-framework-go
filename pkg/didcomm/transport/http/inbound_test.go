/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// mockMsgHandler is an http.msgHandler type, it is similar to MockHandler struct
// but will be injected in WithInboundSetting() directly, will be used by each transport comm handle function
func mockMsgHandler(payload []byte) {
	logger.Debugf("Payload received is %s", payload)
}

func TestInboundHandler(t *testing.T) {
	// test inboundHandler with empty args should fail
	inHandler, err := NewInboundHandler(nil)
	require.Error(t, err)
	require.Nil(t, inHandler)

	// now create a valid inboundHandler to continue testing..
	inHandler, err = NewInboundHandler(mockMsgHandler)

	require.NoError(t, err)
	require.NotNil(t, inHandler)
	server := startMockServer(inHandler)
	port := getServerPort(server)
	serverUrl := fmt.Sprintf("https://localhost:%d", port)
	defer func() {
		e := server.Close()
		if e != nil {
			t.Fatalf("Failed to stop server: %s", e)
		}
	}()

	//build a mock cert pool
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
	rs, err := client.Get(serverUrl + "/")
	require.NoError(t, err)
	require.Equal(t, http.StatusMethodNotAllowed, rs.StatusCode)

	// test accepted HTTP method (POST) but with bad content type
	rs, err = client.Post(serverUrl+"/", "bad-content-type", bytes.NewBuffer([]byte("Hello World")))
	require.NoError(t, err)
	require.Equal(t, http.StatusUnsupportedMediaType, rs.StatusCode)

	// test with nil body ..
	rs, err = client.Post(serverUrl+"/", commContentType, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, rs.StatusCode)

	// finally test successful POST requests
	data := "success"

	resp, e := client.Post(serverUrl+"/", commContentType, bytes.NewBuffer([]byte(data)))
	require.NoError(t, e)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
}
