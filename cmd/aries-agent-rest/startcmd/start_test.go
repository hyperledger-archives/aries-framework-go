/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

type mockServer struct{}

const agentUnexpectedExitErrMsg = "agent server exited unexpectedly"

func (s *mockServer) ListenAndServe(host string, handler http.Handler) error {
	return nil
}

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

	err = listener.Close()
	if err != nil {
		return 0, err
	}

	return listener.Addr().(*net.TCPAddr).Port, nil
}

func TestStartCmdContents(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start an agent", startCmd.Short)
	require.Equal(t, "Start an Aries agent controller", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, agentHostFlagName, agentHostFlagShorthand, agentHostFlagUsage)
	checkFlagPropertiesCorrect(t, startCmd, agentInboundHostFlagName,
		agentInboundHostFlagShorthand, agentInboundHostFlagUsage)
	checkFlagPropertiesCorrect(t, startCmd, agentDBPathFlagName, agentDBPathFlagShorthand, agentDBPathFlagUsage)
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}

func TestStartAriesDRequests(t *testing.T) {
	path, cleanup := generateTempDir(t)
	defer cleanup()

	testHostURL := randomURL()
	testInboundHostURL := randomURL()

	go func() {
		parameters := &agentParameters{server: &HTTPServer{}, host: testHostURL, inboundHostInternal: testInboundHostURL,
			inboundHostExternal: "", dbPath: path, defaultLabel: "x", webhookURLs: []string{},
			httpResolvers: []string{"sample@http://sample.com"}, outboundTransports: []string{}, inboundTransport: ""}
		err := startAgent(parameters)
		require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
	}()

	waitForServerToStart(t, testHostURL, testInboundHostURL)

	validateRequests(t, testHostURL, testInboundHostURL)
}

func listenFor(host string) error {
	timeout := time.After(10 * time.Second)

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

//nolint:funlen
func validateRequests(t *testing.T, testHostURL, testInboundHostURL string) {
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
			r:                  newreq("GET", fmt.Sprintf("http://%s/connections", testHostURL), nil, ""),
			expectedStatus:     http.StatusOK,
			expectResponseData: true,
		},

		// DIDComm inbound API test
		{
			name: "200: testing didcomm inbound",
			r: newreq(http.MethodPost,
				fmt.Sprintf("http://%s", testInboundHostURL),
				strings.NewReader(`
							{
								"@id": "5678876542345",
								"@type": "https://didcomm.org/didexchange/1.0/invitation"
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

func TestStartCmdWithBlankHostArg(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	args := []string{"--" + agentHostFlagName, "", "--" + agentInboundHostFlagName, randomURL(),
		"--" + agentDBPathFlagName, "", "--" + agentWebhookFlagName, ""}
	startCmd.SetArgs(args)

	err = startCmd.Execute()

	require.Equal(t, errMissingHost.Error(), err.Error())
}

func TestStartCmdWithMissingHostArg(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	args := []string{"--" + agentInboundHostFlagName, randomURL(), "--" + agentDBPathFlagName, "",
		"--" + agentWebhookFlagName, ""}
	startCmd.SetArgs(args)

	err = startCmd.Execute()

	require.Equal(t,
		"Neither api-host (command line flag) nor ARIESD_API_HOST (environment variable) have been set.",
		err.Error())
}

func TestStartAgentWithBlankHost(t *testing.T) {
	parameters := &agentParameters{server: &mockServer{}, host: "", inboundHostInternal: randomURL(),
		inboundHostExternal: "", dbPath: "", defaultLabel: "",
		webhookURLs: []string{}, httpResolvers: []string{}, outboundTransports: []string{}, inboundTransport: ""}

	err := startAgent(parameters)
	require.NotNil(t, err)
	require.Equal(t, errMissingHost, err)
}

func TestStartCmdWithoutInboundHostArg(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	args := []string{"--" + agentHostFlagName, randomURL(), "--" + agentDBPathFlagName, "",
		"--" + agentWebhookFlagName, ""}

	startCmd.SetArgs(args)

	err = startCmd.Execute()
	require.NotNil(t, err)
	require.Equal(t,
		"Neither inbound-host (command line flag) nor ARIESD_INBOUND_HOST (environment variable) have been set.",
		err.Error())
}

func TestStartAgentWithBlankInboundHost(t *testing.T) {
	parameters := &agentParameters{server: &mockServer{}, host: randomURL(), inboundHostInternal: "",
		inboundHostExternal: "", dbPath: "", defaultLabel: "",
		webhookURLs: []string{}, httpResolvers: []string{}, outboundTransports: []string{}, inboundTransport: ""}
	err := startAgent(parameters)

	require.Equal(t, errMissingInboundHost, err)
}

func TestStartCmdWithoutDBPath(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	args := []string{"--" + agentHostFlagName, randomURL(), "--" + agentInboundHostFlagName, randomURL(),
		"--" + agentWebhookFlagName, ""}
	startCmd.SetArgs(args)

	err = startCmd.Execute()
	require.Equal(t,
		"Neither db-path (command line flag) nor ARIESD_DB_PATH (environment variable) have been set.",
		err.Error())
}

func TestStartCmdWithoutWebhookURL(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	path, cleanup := generateTempDir(t)
	defer cleanup()

	args := []string{"--" + agentHostFlagName, randomURL(), "--" + agentInboundHostFlagName,
		randomURL(), "--" + agentInboundHostExternalFlagName, randomURL(), "--" + agentDBPathFlagName, path}
	startCmd.SetArgs(args)

	err = startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "webhook-url not set")
}

func TestStartCmdWithoutWebhookURLAndAutoAccept(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	path, cleanup := generateTempDir(t)
	defer cleanup()

	args := []string{"--" + agentHostFlagName, randomURL(), "--" + agentInboundHostFlagName,
		randomURL(), "--" + agentInboundHostExternalFlagName, randomURL(), "--" + agentDBPathFlagName, path,
		"--" + agentAutoAcceptFlagName, "true"}
	startCmd.SetArgs(args)

	err = startCmd.Execute()
	require.NoError(t, err)
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	path, cleanup := generateTempDir(t)
	defer cleanup()

	args := []string{"--" + agentHostFlagName, randomURL(), "--" + agentInboundHostFlagName,
		randomURL(), "--" + agentInboundHostExternalFlagName, randomURL(), "--" + agentDBPathFlagName, path,
		"--" + agentDefaultLabelFlagName, "agent", "--" + agentWebhookFlagName, ""}
	startCmd.SetArgs(args)

	err = startCmd.Execute()

	require.Nil(t, err)
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	err = os.Setenv(agentHostEnvKey, randomURL())
	require.Nil(t, err)
	err = os.Setenv(agentInboundHostEnvKey, randomURL())
	require.Nil(t, err)

	path, cleanup := generateTempDir(t)
	defer cleanup()

	err = os.Setenv(agentDBPathEnvKey, path)
	require.Nil(t, err)
	err = os.Setenv(agentWebhookEnvKey, "")
	require.Nil(t, err)
	err = os.Setenv(agentDefaultLabelEnvKey, "")
	require.Nil(t, err)

	err = startCmd.Execute()

	require.Nil(t, err)
}

func TestStartMultipleAgentsWithSameHost(t *testing.T) {
	host := "localhost:8095"
	inboundHost := "localhost:8096"
	inboundHost2 := "localhost:8097"

	path1, cleanup1 := generateTempDir(t)
	defer cleanup1()

	go func() {
		parameters := &agentParameters{server: &HTTPServer{}, host: host, inboundHostInternal: inboundHost,
			inboundHostExternal: "", dbPath: path1, defaultLabel: "",
			webhookURLs: []string{}, httpResolvers: []string{}, outboundTransports: []string{}, inboundTransport: ""}
		err := startAgent(parameters)
		require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
	}()

	waitForServerToStart(t, host, inboundHost)

	path2, cleanup2 := generateTempDir(t)
	defer cleanup2()

	parameters := &agentParameters{server: &HTTPServer{}, host: host, inboundHostInternal: inboundHost2,
		inboundHostExternal: "", dbPath: path2, defaultLabel: "",
		webhookURLs: []string{}, httpResolvers: []string{}, outboundTransports: []string{}, inboundTransport: ""}

	addressAlreadyInUseErrorMessage := "failed to start aries agent rest on port [" + host +
		"], cause:  listen tcp 127.0.0.1:8095: bind: address already in use"

	err := startAgent(parameters)
	require.NotNil(t, err)
	require.Equal(t, addressAlreadyInUseErrorMessage, err.Error())
}

func TestStartMultipleAgentsWithSameDBPath(t *testing.T) {
	host1 := "localhost:8088"
	host2 := "localhost:8090"
	inboundHost1 := "localhost:8089"
	inboundHost2 := "localhost:8091"

	path, cleanup := generateTempDir(t)
	defer cleanup()

	go func() {
		parameters := &agentParameters{server: &HTTPServer{}, host: host1, inboundHostInternal: inboundHost1,
			inboundHostExternal: "", dbPath: path, defaultLabel: "",
			webhookURLs: []string{}, httpResolvers: []string{}, outboundTransports: []string{}, inboundTransport: ""}

		err := startAgent(parameters)
		require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
	}()

	waitForServerToStart(t, host1, inboundHost1)

	parameters := &agentParameters{server: &HTTPServer{}, host: host2, inboundHostInternal: inboundHost2,
		inboundHostExternal: "", dbPath: path, defaultLabel: "",
		webhookURLs: []string{}, httpResolvers: []string{}, outboundTransports: []string{}, inboundTransport: ""}
	err := startAgent(parameters)

	require.NotNil(t, err)
	require.Contains(t, err.Error(), "failed to OpenStore for")
}

func TestStartAriesErrorWithResolvers(t *testing.T) {
	t.Run("start aries with resolver - invalid resolver error", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()

		testHostURL := randomURL()
		testInboundHostURL := randomURL()

		parameters := &agentParameters{server: &HTTPServer{}, host: testHostURL, inboundHostInternal: testInboundHostURL,
			inboundHostExternal: "", dbPath: path, defaultLabel: "x",
			webhookURLs: []string{}, httpResolvers: []string{"http://sample.com"},
			outboundTransports: []string{}, inboundTransport: ""}

		err := startAgent(parameters)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid http resolver options found")
	})

	t.Run("start aries with resolver - url invalid error", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()

		testHostURL := randomURL()
		testInboundHostURL := randomURL()

		parameters := &agentParameters{server: &HTTPServer{}, host: testHostURL, inboundHostInternal: testInboundHostURL,
			inboundHostExternal: "", dbPath: path, defaultLabel: "x",
			webhookURLs: []string{}, httpResolvers: []string{"@h"},
			outboundTransports: []string{}, inboundTransport: ""}
		err := startAgent(parameters)
		require.Error(t, err)
		require.Contains(t, err.Error(), " base URL invalid")
	})
}

func TestStartAriesWithOutboundTransports(t *testing.T) {
	t.Run("start aries with outbound transports success", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()

		testHostURL := randomURL()
		testInboundHostURL := randomURL()

		go func() {
			parameters := &agentParameters{server: &HTTPServer{}, host: testHostURL, inboundHostInternal: testInboundHostURL,
				inboundHostExternal: "", dbPath: path, defaultLabel: "x",
				webhookURLs: []string{}, httpResolvers: []string{},
				outboundTransports: []string{"http", "ws"}, inboundTransport: ""}

			err := startAgent(parameters)
			require.NoError(t, err)
			require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
		}()

		waitForServerToStart(t, testHostURL, testInboundHostURL)
	})

	t.Run("start aries with outbound transport wrong flag", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()

		testHostURL := randomURL()
		testInboundHostURL := randomURL()

		parameters := &agentParameters{server: &HTTPServer{}, host: testHostURL, inboundHostInternal: testInboundHostURL,
			inboundHostExternal: "", dbPath: path, defaultLabel: "x",
			webhookURLs: []string{}, httpResolvers: []string{},
			outboundTransports: []string{"http", "wss"}, inboundTransport: ""}
		err := startAgent(parameters)
		require.Error(t, err)
		require.Contains(t, err.Error(), "outbound transport [wss] not supported")
	})
}

func TestStartAriesWithInboundTransport(t *testing.T) {
	t.Run("start aries with inbound transports success", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()

		testHostURL := randomURL()
		testInboundHostURL := randomURL()

		go func() {
			parameters := &agentParameters{server: &HTTPServer{}, host: testHostURL, inboundHostInternal: testInboundHostURL,
				inboundHostExternal: "", dbPath: path, defaultLabel: "x",
				webhookURLs: []string{}, httpResolvers: []string{},
				outboundTransports: []string{}, inboundTransport: "ws"}

			err := startAgent(parameters)
			require.NoError(t, err)
			require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
		}()

		waitForServerToStart(t, testHostURL, testInboundHostURL)
	})

	t.Run("start aries with inbound transport wrong flag", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()

		testHostURL := randomURL()
		testInboundHostURL := randomURL()

		parameters := &agentParameters{server: &HTTPServer{}, host: testHostURL, inboundHostInternal: testInboundHostURL,
			inboundHostExternal: "", dbPath: path, defaultLabel: "x",
			webhookURLs: []string{}, httpResolvers: []string{},
			outboundTransports: []string{}, inboundTransport: "wss"}
		err := startAgent(parameters)
		require.Error(t, err)
		require.Contains(t, err.Error(), "inbound transport [wss] not supported")
	})
}

func TestStartAriesWithAutoAccept(t *testing.T) {
	t.Run("start aries with auto accept success", func(t *testing.T) {
		path, cleanup := generateTempDir(t)
		defer cleanup()

		testHostURL := randomURL()
		testInboundHostURL := randomURL()

		go func() {
			parameters := &agentParameters{server: &HTTPServer{}, host: testHostURL, inboundHostInternal: testInboundHostURL,
				inboundHostExternal: "", dbPath: path, defaultLabel: "x",
				webhookURLs: []string{}, httpResolvers: []string{},
				outboundTransports: []string{}, inboundTransport: "", autoAccept: true}

			err := startAgent(parameters)
			require.NoError(t, err)
			require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
		}()

		waitForServerToStart(t, testHostURL, testInboundHostURL)
	})
}

func waitForServerToStart(t *testing.T, host, inboundHost string) {
	if err := listenFor(host); err != nil {
		t.Fatal(err)
	}

	if err := listenFor(inboundHost); err != nil {
		t.Fatal(err)
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
