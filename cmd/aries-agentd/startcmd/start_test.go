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

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

type mockServer struct{}

const agentUnexpectedExitErrMsg = "agent server exited unexpectedly"

func (s *mockServer) ListenAndServe(host string, router *mux.Router) error {
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
	if err := listener.Close(); err != nil {
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

	checkFlagPropertiesCorrect(t, startCmd, AgentHostFlagName, AgentHostFlagShorthand, AgentHostFlagUsage)
	checkFlagPropertiesCorrect(t, startCmd, AgentInboundHostFlagName,
		AgentInboundHostFlagShorthand, AgentInboundHostFlagUsage)
	checkFlagPropertiesCorrect(t, startCmd, AgentDBPathFlagName, AgentDBPathFlagShorthand, AgentDBPathFlagUsage)
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Len(t, flagAnnotations, 1)
	requiredFlagKeyName := "cobra_annotation_bash_completion_one_required_flag"
	require.Contains(t, flagAnnotations, requiredFlagKeyName)
	requiredFlagAnnotation := flagAnnotations[requiredFlagKeyName]
	require.Len(t, requiredFlagAnnotation, 1)
	require.Equal(t, requiredFlagAnnotation[0], "true")
}

func TestStartAriesDRequests(t *testing.T) {
	// TODO - remove this path manipulation after implementing #175 and #148
	path, cleanup := generateTempDir(t)
	defer cleanup()

	testHostURL := randomURL()
	testInboundHostURL := randomURL()

	go func() {
		parameters := &agentParameters{&HTTPServer{}, testHostURL, testInboundHostURL, path, []string{}}
		err := startAgent(parameters)
		require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
	}()

	waitForServerToStart(t, testHostURL, testInboundHostURL)

	validateRequests(t, testHostURL, testInboundHostURL)
}

func listenFor(host string) error {
	timeout := time.After(5 * time.Second)
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

// TODO: this method should be refactored (e.g., too many lines).
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
			r:                  newreq("GET", fmt.Sprintf("http://%s/connections/create-invitation", testHostURL), nil, ""),
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

func TestStartCmdWithMissingHostArg(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)
	args := []string{"--" + AgentInboundHostFlagName, randomURL(), "--" + AgentDBPathFlagName, "",
		"--" + AgentWebhookFlagName, ""}
	startCmd.SetArgs(args)

	err = startCmd.Execute()

	require.NotNil(t, err)
	require.Equal(t, `required flag(s) "api-host" not set`, err.Error())
}

func TestStartAgentWithBlankHost(t *testing.T) {
	parameters := &agentParameters{&mockServer{}, "", randomURL(), "", []string{}}
	err := startAgent(parameters)

	require.NotNil(t, err)
	require.Equal(t, ErrMissingHost, err)
}

func TestStartCmdWithoutInboundHostArg(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)
	args := []string{"--" + AgentHostFlagName, randomURL(), "--" + AgentDBPathFlagName, "",
		"--" + AgentWebhookFlagName, ""}
	startCmd.SetArgs(args)

	err = startCmd.Execute()

	require.NotNil(t, err)
	require.Equal(t, `required flag(s) "inbound-host" not set`, err.Error())
}

func TestStartAgentWithBlankInboundHost(t *testing.T) {
	parameters := &agentParameters{&mockServer{}, randomURL(), "", "", []string{}}
	err := startAgent(parameters)

	require.NotNil(t, err)
	require.Equal(t, ErrMissingInboundHost, err)
	if err == nil {
		t.Fatal()
	}
}

func TestStartCmdWithoutDBPath(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)
	args := []string{"--" + AgentHostFlagName, randomURL(), "--" + AgentInboundHostFlagName, randomURL(),
		"--" + AgentWebhookFlagName, ""}
	startCmd.SetArgs(args)

	err = startCmd.Execute()

	require.NotNil(t, err)
	require.Equal(t, `required flag(s) "db-path" not set`, err.Error())
}

func TestStartCmdMissingAllArgs(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	err = startCmd.Execute()
	require.NotNil(t, err)
	require.Equal(t,
		`required flag(s) "api-host", "db-path", "inbound-host", "webhook-url" not set`, err.Error())
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)
	args := []string{"--" + AgentHostFlagName, randomURL(), "--" + AgentInboundHostFlagName,
		randomURL(), "--" + AgentDBPathFlagName, "", "--" + AgentWebhookFlagName, ""}
	startCmd.SetArgs(args)

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
		parameters := &agentParameters{&HTTPServer{}, host, inboundHost, path1, []string{}}
		err := startAgent(parameters)
		require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
	}()

	waitForServerToStart(t, host, inboundHost)

	path2, cleanup2 := generateTempDir(t)
	defer cleanup2()
	parameters := &agentParameters{&HTTPServer{}, host, inboundHost2, path2, []string{}}
	err := startAgent(parameters)

	require.NotNil(t, err)
	addressAlreadyInUseErrorMessage := "failed to start aries agentd on port [" + host +
		"], cause:  listen tcp 127.0.0.1:8095: bind: address already in use"
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
		parameters := &agentParameters{&HTTPServer{}, host1, inboundHost1, path, []string{}}
		err := startAgent(parameters)
		require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
	}()

	waitForServerToStart(t, host1, inboundHost1)

	parameters := &agentParameters{&HTTPServer{}, host2, inboundHost2, path, []string{}}
	err := startAgent(parameters)

	require.NotNil(t, err)
	require.Contains(t, err.Error(), "storage initialization failed")
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
