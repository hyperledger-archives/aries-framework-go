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

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

type mockServer struct{}

const agentUnexpectedExitErrMsg = "agent server exited unexpectedly"

func (s *mockServer) ListenAndServe(host string, handler http.Handler, certFile, keyFile string) error {
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

	checkFlagPropertiesCorrect(t, startCmd, agentHostFlagName, agentHostFlagShorthand, agentHostFlagUsage, "")
	checkFlagPropertiesCorrect(t, startCmd, agentInboundHostFlagName,
		agentInboundHostFlagShorthand, agentInboundHostFlagUsage, "[]")
	checkFlagPropertiesCorrect(t, startCmd, databaseTypeFlagName, databaseTypeFlagShorthand, databaseTypeFlagUsage, "")
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName,
	flagShorthand, flagUsage, expectedVal string) {
	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, expectedVal, flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}

func TestStartAriesDRequests(t *testing.T) {
	testHostURL := randomURL()
	testInboundHostURL := randomURL()

	go func() {
		parameters := &agentParameters{
			server:               &HTTPServer{},
			host:                 testHostURL,
			inboundHostInternals: []string{httpProtocol + "@" + testInboundHostURL},
			dbParam:              &dbParam{dbType: databaseTypeMemOption},
			defaultLabel:         "x",
			httpResolvers:        []string{"sample@http://sample.com"},
			transportReturnRoute: "all",
		}
		err := startAgent(parameters)
		require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
	}()

	waitForServerToStart(t, testHostURL, testInboundHostURL)

	validateRequests(t, testHostURL, "", testInboundHostURL)
}

func listenFor(host string) error {
	timeout := time.After(10 * time.Second)

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout: %s is not available", host)
		default:
			conn, err := net.Dial("tcp", host)
			if err != nil {
				continue
			}

			return conn.Close()
		}
	}
}

type requestTestParams struct {
	name               string //nolint:structcheck
	r                  *http.Request
	expectedStatus     int
	expectResponseData bool
}

func runRequestTests(t *testing.T, tests []requestTestParams) {
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

//nolint:funlen
func validateRequests(t *testing.T, testHostURL, authorizationHdr, testInboundHostURL string) {
	newreq := func(method, url string, body io.Reader, contentType string) *http.Request {
		r, err := http.NewRequest(method, url, body)

		if contentType != "" {
			r.Header.Add("Content-Type", contentType)
		}

		if authorizationHdr != "" {
			r.Header.Add("Authorization", authorizationHdr)
		}

		if err != nil {
			t.Fatal(err)
		}

		return r
	}

	tests := []requestTestParams{
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

	runRequestTests(t, tests)
}

func validateUnauthorized(t *testing.T, testHostURL, authorizationHdr string) {
	newreq := func(method, url string, body io.Reader, contentType string) *http.Request {
		r, err := http.NewRequest(method, url, body)

		if contentType != "" {
			r.Header.Add("Content-Type", contentType)
		}

		if authorizationHdr != "" {
			r.Header.Add("Authorization", authorizationHdr)
		}

		if err != nil {
			t.Fatal(err)
		}

		return r
	}

	tests := []requestTestParams{
		// controller API test
		{
			name:               "1: testing get",
			r:                  newreq("GET", fmt.Sprintf("http://%s/connections", testHostURL), nil, ""),
			expectedStatus:     http.StatusUnauthorized,
			expectResponseData: false,
		},
	}

	runRequestTests(t, tests)
}

// isJSON checks if response is json.
func isJSON(res []byte) bool {
	var js map[string]interface{}
	return json.Unmarshal(res, &js) == nil
}

func TestStartCmdWithBlankHostArg(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	args := []string{
		"--" + agentHostFlagName, "", "--" + agentInboundHostFlagName, randomURL(),
		"--" + databaseTypeFlagName, databaseTypeMemOption, "--" + agentWebhookFlagName, "",
	}
	startCmd.SetArgs(args)

	err = startCmd.Execute()

	require.Equal(t, errMissingHost.Error(), err.Error())
}

func TestStartCmdWithMissingHostArg(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	args := []string{
		"--" + agentInboundHostFlagName, randomURL(), "--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + agentWebhookFlagName, "",
	}
	startCmd.SetArgs(args)

	err = startCmd.Execute()

	require.Equal(t,
		"Neither api-host (command line flag) nor ARIESD_API_HOST (environment variable) have been set.",
		err.Error())
}

func TestStartAgentWithBlankHost(t *testing.T) {
	parameters := &agentParameters{
		server:               &mockServer{},
		inboundHostInternals: []string{randomURL()},
	}

	err := startAgent(parameters)
	require.NotNil(t, err)
	require.Equal(t, errMissingHost, err)
}

func TestStartCmdWithoutInboundHostArg(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	args := []string{
		"--" + agentHostFlagName, randomURL(), "--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + agentWebhookFlagName, "",
	}

	startCmd.SetArgs(args)

	err = startCmd.Execute()
	require.NoError(t, err)
}

func TestStartCmdWithoutDBType(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	args := []string{
		"--" + agentHostFlagName,
		randomURL(),
		"--" + agentInboundHostFlagName,
		randomURL(),
		"--" + agentWebhookFlagName,
		"",
	}
	startCmd.SetArgs(args)

	err = startCmd.Execute()
	require.Equal(t,
		"Neither database-type (command line flag) nor ARIESD_DATABASE_TYPE (environment variable) have been set.",
		err.Error())
}

func TestStartCmdWithoutWebhookURL(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	args := []string{
		"--" + agentHostFlagName,
		randomURL(),
		"--" + agentInboundHostFlagName,
		httpProtocol + "@" + randomURL(),
		"--" + agentInboundHostExternalFlagName,
		httpProtocol + "@" + randomURL(),
		"--" + databaseTypeFlagName,
		databaseTypeMemOption,
	}
	startCmd.SetArgs(args)

	err = startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "webhook-url not set")
}

func TestStartCmdWithLogLevel(t *testing.T) {
	t.Run("start with log level - success", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName,
			randomURL(),
			"--" + agentInboundHostFlagName,
			httpProtocol + "@" + randomURL(),
			"--" + agentInboundHostExternalFlagName,
			httpProtocol + "@" + randomURL(),
			"--" + databaseTypeFlagName,
			databaseTypeMemOption,
			"--" + agentAutoAcceptFlagName,
			"true",
			"--" + agentLogLevelFlagName,
			"DEBUG",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("start with log level - invalid", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentLogLevelFlagName,
			"INVALID",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid log level")
	})

	t.Run("validate log level", func(t *testing.T) {
		err := setLogLevel("DEBUG")
		require.NoError(t, err)
		require.Equal(t, log.DEBUG, log.GetLevel(""))

		err = setLogLevel("WARNING")
		require.NoError(t, err)
		require.Equal(t, log.WARNING, log.GetLevel(""))

		err = setLogLevel("CRITICAL")
		require.NoError(t, err)
		require.Equal(t, log.CRITICAL, log.GetLevel(""))

		err = setLogLevel("ERROR")
		require.NoError(t, err)
		require.Equal(t, log.ERROR, log.GetLevel(""))

		err = setLogLevel("INFO")
		require.NoError(t, err)
		require.Equal(t, log.INFO, log.GetLevel(""))

		err = setLogLevel("")
		require.NoError(t, err)
		require.Equal(t, log.INFO, log.GetLevel(""))

		err = setLogLevel("INVALID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid log level")
	})
}

func TestStartCmdWithoutWebhookURLAndAutoAccept(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	args := []string{
		"--" + agentHostFlagName,
		randomURL(),
		"--" + agentInboundHostFlagName,
		httpProtocol + "@" + randomURL(),
		"--" + agentInboundHostExternalFlagName,
		httpProtocol + "@" + randomURL(),
		"--" + databaseTypeFlagName,
		databaseTypeMemOption,
		"--" + agentAutoAcceptFlagName,
		"true",
	}
	startCmd.SetArgs(args)

	err = startCmd.Execute()
	require.NoError(t, err)
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	args := []string{
		"--" + agentHostFlagName,
		randomURL(),
		"--" + agentInboundHostFlagName,
		httpProtocol + "@" + randomURL(),
		"--" + agentInboundHostExternalFlagName,
		httpProtocol + "@" + randomURL(),
		"--" + databaseTypeFlagName,
		databaseTypeMemOption,
		"--" + agentDefaultLabelFlagName,
		"agent",
		"--" + agentWebhookFlagName,
		"",
	}
	startCmd.SetArgs(args)

	err = startCmd.Execute()

	require.Nil(t, err)
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	err = os.Setenv(agentHostEnvKey, randomURL())
	require.Nil(t, err)
	err = os.Setenv(agentInboundHostEnvKey, httpProtocol+"@"+randomURL())
	require.Nil(t, err)

	err = os.Setenv(databaseTypeEnvKey, databaseTypeMemOption)
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

	go func() {
		parameters := &agentParameters{
			server:               &HTTPServer{},
			host:                 host,
			inboundHostInternals: []string{httpProtocol + "@" + inboundHost},
			dbParam:              &dbParam{dbType: databaseTypeMemOption},
			defaultLabel:         "",
		}
		err := startAgent(parameters)
		require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
	}()

	waitForServerToStart(t, host, inboundHost)

	parameters := &agentParameters{
		server:               &HTTPServer{},
		host:                 host,
		inboundHostInternals: []string{httpProtocol + "@" + inboundHost2},
		dbParam:              &dbParam{dbType: databaseTypeMemOption},
	}

	addressAlreadyInUseErrorMessage := "failed to start aries agent rest on port [" + host +
		"], cause:  listen tcp 127.0.0.1:8095: bind: address already in use"

	err := startAgent(parameters)
	require.NotNil(t, err)
	require.Equal(t, addressAlreadyInUseErrorMessage, err.Error())
}

func TestStartAriesErrorWithResolvers(t *testing.T) {
	t.Run("start aries with resolver - invalid resolver error", func(t *testing.T) {
		testHostURL := randomURL()
		testInboundHostURL := randomURL()

		parameters := &agentParameters{
			server:               &HTTPServer{},
			host:                 testHostURL,
			inboundHostInternals: []string{httpProtocol + "@" + testInboundHostURL},
			dbParam:              &dbParam{dbType: databaseTypeMemOption},
			defaultLabel:         "x",
			httpResolvers:        []string{"http://sample.com"},
		}

		err := startAgent(parameters)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid http resolver options found")
	})

	t.Run("start aries with resolver - url invalid error", func(t *testing.T) {
		testHostURL := randomURL()
		testInboundHostURL := randomURL()

		parameters := &agentParameters{
			server:               &HTTPServer{},
			host:                 testHostURL,
			inboundHostInternals: []string{httpProtocol + "@" + testInboundHostURL},
			dbParam:              &dbParam{dbType: databaseTypeMemOption},
			defaultLabel:         "x",
			httpResolvers:        []string{"@h"},
		}
		err := startAgent(parameters)
		require.Error(t, err)
		require.Contains(t, err.Error(), " base URL invalid")
	})
}

func TestStartAriesWithOutboundTransports(t *testing.T) {
	t.Run("start aries with outbound transports success", func(t *testing.T) {
		testHostURL := randomURL()
		testInboundHostURL := randomURL()

		go func() {
			parameters := &agentParameters{
				server:               &HTTPServer{},
				host:                 testHostURL,
				inboundHostInternals: []string{httpProtocol + "@" + testInboundHostURL},
				dbParam:              &dbParam{dbType: databaseTypeMemOption},
				defaultLabel:         "x",
				outboundTransports:   []string{"http", "ws"},
			}

			err := startAgent(parameters)
			require.NoError(t, err)
			require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
		}()

		waitForServerToStart(t, testHostURL, testInboundHostURL)
	})

	t.Run("start aries with outbound transport wrong flag", func(t *testing.T) {
		testHostURL := randomURL()
		testInboundHostURL := randomURL()

		parameters := &agentParameters{
			server:               &HTTPServer{},
			host:                 testHostURL,
			inboundHostInternals: []string{httpProtocol + "@" + testInboundHostURL},
			dbParam:              &dbParam{dbType: databaseTypeMemOption},
			defaultLabel:         "x",
			outboundTransports:   []string{"http", "wss"},
		}
		err := startAgent(parameters)
		require.Error(t, err)
		require.Contains(t, err.Error(), "outbound transport [wss] not supported")
	})
}

func TestStartAriesWithInboundTransport(t *testing.T) {
	t.Run("start aries with inbound transports success", func(t *testing.T) {
		testHostURL := randomURL()
		testInboundHostURL := randomURL()

		go func() {
			parameters := &agentParameters{
				server:               &HTTPServer{},
				host:                 testHostURL,
				inboundHostInternals: []string{websocketProtocol + "@" + testInboundHostURL},
				dbParam:              &dbParam{dbType: databaseTypeMemOption},
				defaultLabel:         "x",
			}

			err := startAgent(parameters)
			require.NoError(t, err)
			require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
		}()

		waitForServerToStart(t, testHostURL, testInboundHostURL)
	})

	t.Run("start aries with inbound transport wrong flag", func(t *testing.T) {
		testHostURL := randomURL()
		testInboundHostURL := randomURL()

		parameters := &agentParameters{
			server:               &HTTPServer{},
			host:                 testHostURL,
			inboundHostInternals: []string{"wss" + "@" + testInboundHostURL},
			dbParam:              &dbParam{dbType: databaseTypeMemOption},
			defaultLabel:         "x",
		}
		err := startAgent(parameters)
		require.Error(t, err)
		require.Contains(t, err.Error(), "inbound transport [wss] not supported")
	})
}

func TestStartAriesWithAutoAccept(t *testing.T) {
	t.Run("start aries with auto accept success", func(t *testing.T) {
		testHostURL := randomURL()
		testInboundHostURL := randomURL()

		go func() {
			parameters := &agentParameters{
				server:               &HTTPServer{},
				host:                 testHostURL,
				inboundHostInternals: []string{httpProtocol + "@" + testInboundHostURL},
				dbParam:              &dbParam{dbType: databaseTypeMemOption},
				defaultLabel:         "x",
				autoAccept:           true,
			}

			err := startAgent(parameters)
			require.NoError(t, err)
			require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
		}()

		waitForServerToStart(t, testHostURL, testInboundHostURL)
	})
}

func TestStartAriesTLS(t *testing.T) {
	parameters := &agentParameters{
		server:      &HTTPServer{},
		host:        ":0",
		dbParam:     &dbParam{dbType: databaseTypeMemOption},
		tlsCertFile: "invalid",
		tlsKeyFile:  "invalid",
	}

	err := startAgent(parameters)
	require.EqualError(t, errors.Unwrap(err), "open invalid: no such file or directory")
}

func TestStartAriesWithAuthorization(t *testing.T) {
	const (
		goodToken = "ABCD"
		badToken  = "BCDE"
	)

	testHostURL := randomURL()
	testInboundHostURL := randomURL()

	go func() {
		parameters := &agentParameters{
			server:               &HTTPServer{},
			host:                 testHostURL,
			token:                goodToken,
			inboundHostInternals: []string{httpProtocol + "@" + testInboundHostURL},
			dbParam:              &dbParam{dbType: databaseTypeMemOption},
			defaultLabel:         "x",
		}

		err := startAgent(parameters)
		require.NoError(t, err)
		require.FailNow(t, agentUnexpectedExitErrMsg+": "+err.Error())
	}()

	waitForServerToStart(t, testHostURL, testInboundHostURL)

	t.Run("use good authorization token", func(t *testing.T) {
		authorizationHdr := "Bearer " + goodToken
		validateRequests(t, testHostURL, authorizationHdr, testInboundHostURL)
	})

	t.Run("use bad authorization token", func(t *testing.T) {
		authorizationHdr := "Bearer " + badToken
		validateUnauthorized(t, testHostURL, authorizationHdr)
	})

	t.Run("use no authorization token", func(t *testing.T) {
		authorizationHdr := "Bearer"
		validateUnauthorized(t, testHostURL, authorizationHdr)
	})

	t.Run("use no authorization header", func(t *testing.T) {
		authorizationHdr := ""
		validateUnauthorized(t, testHostURL, authorizationHdr)
	})
}

func TestStoreProvider(t *testing.T) {
	t.Run("test invalid database type", func(t *testing.T) {
		_, err := createAriesAgent(&agentParameters{dbParam: &dbParam{dbType: "data1"}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "database type not set to a valid type")
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
