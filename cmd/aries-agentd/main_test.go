/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func randomURL() string {
	return fmt.Sprintf("localhost:%d", mustGetRandomPort(3))
}

func mustGetRandomPort(n int) int {
	for ; n > 0; n-- {
		port, err := getRandomPort()
		if err != nil {
			continue
		}
		return port
	}
	panic("cannot acquire the random port")
}

func getRandomPort() (int, error) {
	const network = "tcp"
	addr, err := net.ResolveTCPAddr(network, "localhost:0")
	if err != nil {
		return 0, err
	}
	listener, err := net.ListenTCP(network, addr)
	if err != nil {
		return 0, err
	}
	if err := listener.Close(); err != nil {
		return 0, err
	}
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func TestStartAriesD(t *testing.T) {
	// TODO - remove this path manipulation after implementing #175 and #148
	path, cleanup := generateTempDir(t)
	defer cleanup()

	err := os.Setenv(agentDBPathEnvKey, path)
	if err != nil {
		t.Fatal(err)
	}

	prev := os.Getenv(agentHostEnvKey)
	defer func() {
		err = os.Setenv(agentHostEnvKey, prev)
		if err != nil {
			t.Fatal(err)
		}
	}()

	testURL := randomURL()
	err = os.Setenv(agentHostEnvKey, testURL)
	if err != nil {
		t.Fatal(err)
	}

	prevInboundPort := os.Getenv(agentHTTPInboundEnvKey)
	defer func() {
		inboundConfigErr := os.Setenv(agentHTTPInboundEnvKey, prevInboundPort)
		if inboundConfigErr != nil {
			t.Fatal(inboundConfigErr)
		}
	}()

	testInboundURL := randomURL()
	err = os.Setenv(agentHTTPInboundEnvKey, testInboundURL)
	if err != nil {
		t.Fatal(err)
	}

	go main()
	// give some time for server to start
	if err := listenFor(testURL, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := listenFor(testInboundURL, time.Second); err != nil {
		t.Fatal(err)
	}

	validateRequests(t, testURL, testInboundURL)
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
			if err := conn.Close(); err != nil {
				return err
			}
			return nil
		}
	}
}

// TODO: this method should be refactored (e.g., too many lines).
//nolint:funlen
func validateRequests(t *testing.T, testURL, testInboundURL string) {
	newreq := func(method, url string, body io.Reader, contentType string) *http.Request {
		r, err := http.NewRequest(method, url, body)
		if contentType != "" {
			r.Header.Add("Content-Type", contentType)
		}
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	tests := []struct {
		name               string
		r                  *http.Request
		expectedStatus     int
		expectResponseData bool
	}{
		// controller API test
		{
			name:               "1: testing get",
			r:                  newreq("GET", fmt.Sprintf("http://%s/connections/create-invitation", testURL), nil, ""),
			expectedStatus:     http.StatusOK,
			expectResponseData: true,
		},

		// DIDComm inbound API test
		{
			name: "200: testing didcomm inbound",
			r: newreq("POST",
				fmt.Sprintf("http://%s", testInboundURL),
				strings.NewReader(`
							{
								"@id": "5678876542345",
								"@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation"
							}`),
				"application/didcomm-envelope-enc"),
			expectedStatus:     http.StatusInternalServerError,
			expectResponseData: false,
		},
	}

	for _, tt := range tests {

		resp, err := http.DefaultClient.Do(tt.r)
		if err != nil {
			t.Fatal(err)
		}

		defer func() {
			e := resp.Body.Close()
			if e != nil {
				panic(err)
			}
		}()

		require.Equal(t, tt.expectedStatus, resp.StatusCode)
		if tt.expectResponseData {
			require.NotEmpty(t, resp.Body)
			response, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			require.NotEmpty(t, response)
			require.True(t, isJSON(response))
		}
	}

}

// isJSON checks if response is json
func isJSON(res []byte) bool {
	var js map[string]interface{}
	return json.Unmarshal(res, &js) == nil

}

func TestStartAriesDWithoutHost(t *testing.T) {

	prev := os.Getenv(agentHostEnvKey)
	defer func() {
		err := os.Setenv(agentHostEnvKey, prev)
		if err != nil {
			t.Fatal(err)
		}
	}()

	err := os.Setenv(agentHostEnvKey, "")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan bool)

	go func() {
		main()
		done <- true
	}()

	select {
	case res := <-done:
		require.True(t, res)
	case <-time.After(5 * time.Second):
		t.Fatal("agent should fail to start when host address not provided")
	}

}

func TestStartAriesWithoutInboundHost(t *testing.T) {

	prev := os.Getenv(agentHostEnvKey)
	defer func() {
		err := os.Setenv(agentHostEnvKey, prev)
		if err != nil {
			t.Fatal(err)
		}
	}()

	err := os.Setenv(agentHostEnvKey, randomURL())
	if err != nil {
		t.Fatal(err)
	}

	prevInboundHost := os.Getenv(agentHTTPInboundEnvKey)
	defer func() {
		inboundConfigErr := os.Setenv(agentHTTPInboundEnvKey, prevInboundHost)
		if inboundConfigErr != nil {
			t.Fatal(inboundConfigErr)
		}
	}()

	err = os.Setenv(agentHTTPInboundEnvKey, "")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan bool)

	go func() {
		main()
		done <- true
	}()

	select {
	case res := <-done:
		require.True(t, res)
	case <-time.After(5 * time.Second):
		t.Fatal("agent should fail to start when inbound host address not provided")
	}

}

func generateTempDir(t testing.TB) (string, func()) {
	path, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Failed to create leveldb directory: %s", err)
	}
	return path, func() {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clear leveldb directory: %s", err)
		}
	}
}
