/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/spf13/cobra"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	"github.com/hyperledger/aries-framework-go/pkg/restapi"
)

const (
	agentHostFlagName = "api-host"

	agentHostFlagShorthand = "a"

	agentHostFlagUsage = "Host Name:Port." +
		" Alternatively, this can be set with the following environment variable: " + agentHostEnvKey

	agentHostEnvKey = "ARIESD_API_HOST"

	agentInboundHostFlagName = "inbound-host"

	agentInboundHostFlagShorthand = "i"

	agentInboundHostFlagUsage = "Inbound Host Name:Port. This is used internally to start the inbound server." +
		" Alternatively, this can be set with the following environment variable: " + agentInboundHostEnvKey

	agentInboundHostEnvKey = "ARIESD_INBOUND_HOST"

	agentInboundHostExternalFlagName = "inbound-host-external"

	agentInboundHostExternalFlagShorthand = "e"

	agentInboundHostExternalFlagUsage = "Inbound Host External Name:Port." +
		" This is the URL for the inbound server as seen externally." +
		" If not provided, then the internal inbound host will be used here." +
		" Alternatively, this can be set with the following environment variable: " + agentInboundHostExternalEnvKey

	agentInboundHostExternalEnvKey = "ARIESD_INBOUND_HOST_EXTERNAL"

	agentDBPathFlagName = "db-path"

	agentDBPathFlagShorthand = "d"

	agentDBPathFlagUsage = "Path to database." +
		" Alternatively, this can be set with the following environment variable: " + agentDBPathEnvKey

	agentDBPathEnvKey = "ARIESD_DB_PATH"

	agentWebhookFlagName = "webhook-url"

	agentWebhookFlagShorthand = "w"

	agentWebhookFlagUsage = "URL to send notifications to." +
		" This flag can be repeated, allowing for multiple listeners." +
		" Alternatively, this can be set with the following environment variable (in CSV format): " + agentWebhookEnvKey

	agentWebhookEnvKey = "ARIESD_WEBHOOK_URL"

	agentDefaultLabelFlagName = "agent-default-label"

	agentDefaultLabelFlagShorthand = "l"

	agentDefaultLabelFlagUsage = "Default Label for this agent. Defaults to blank if not set." +
		" Alternatively, this can be set with the following environment variable: " + agentDefaultLabelEnvKey

	agentDefaultLabelEnvKey = "ARIESD_DEFAULT_LABEL"

	unableToStartAgentErrMsg = "unable to start agent"
)

var errMissingHost = errors.New("host not provided")

var errMissingInboundHost = errors.New("HTTP Inbound transport host not provided")

var logger = log.New("aries-framework/agentd")

type agentParameters struct {
	server                                                               server
	host, inboundHostInternal, inboundHostExternal, dbPath, defaultLabel string
	webhookURLs                                                          []string
}

type server interface {
	ListenAndServe(host string, router http.Handler) error
}

// HTTPServer represents an actual server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host string, router http.Handler) error {
	return http.ListenAndServe(host, router)
}

// Cmd returns the Cobra start command.
func Cmd(server server) (*cobra.Command, error) {
	var webhookURLsFromCmdLine []string

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start an agent",
		Long:  `Start an Aries agent controller`,

		RunE: func(cmd *cobra.Command, args []string) error {
			host, err := getUserSetVar(cmd, agentHostFlagName, agentHostEnvKey, false)
			if err != nil {
				return err
			}

			inboundHost, err := getUserSetVar(cmd, agentInboundHostFlagName, agentInboundHostEnvKey, false)
			if err != nil {
				return err
			}

			dbPath, err := getUserSetVar(cmd, agentDBPathFlagName, agentDBPathEnvKey, false)
			if err != nil {
				return err
			}

			inboundHostExternal, err := getUserSetVar(cmd, agentInboundHostExternalFlagName,
				agentInboundHostExternalEnvKey, true)
			if err != nil {
				return err
			}

			defaultLabel, err := getUserSetVar(cmd, agentDefaultLabelFlagName, agentDefaultLabelEnvKey, true)
			if err != nil {
				return err
			}

			webhookURLs, err := getWebhookURLs(cmd, webhookURLsFromCmdLine)
			if err != nil {
				return err
			}

			parameters := &agentParameters{server, host, inboundHost,
				inboundHostExternal, dbPath, defaultLabel, webhookURLs}
			err = startAgent(parameters)
			if err != nil {
				return errors.New(unableToStartAgentErrMsg + ": " + err.Error())
			}

			return nil
		},
	}

	createFlags(startCmd, &webhookURLsFromCmdLine)

	return startCmd, nil
}

func createFlags(startCmd *cobra.Command, webhookURLs *[]string) {
	startCmd.Flags().StringP(agentHostFlagName, agentHostFlagShorthand, "", agentHostFlagUsage)
	startCmd.Flags().StringP(agentInboundHostFlagName, agentInboundHostFlagShorthand, "", agentInboundHostFlagUsage)
	startCmd.Flags().StringP(agentDBPathFlagName, agentDBPathFlagShorthand, "", agentDBPathFlagUsage)
	startCmd.Flags().StringSliceVarP(webhookURLs, agentWebhookFlagName, agentWebhookFlagShorthand, []string{},
		agentWebhookFlagUsage)
	startCmd.Flags().StringP(agentInboundHostExternalFlagName, agentInboundHostExternalFlagShorthand,
		"", agentInboundHostExternalFlagUsage)
	startCmd.Flags().StringP(agentDefaultLabelFlagName, agentDefaultLabelFlagShorthand, "",
		agentDefaultLabelFlagUsage)
}

func getUserSetVar(cmd *cobra.Command, hostFlagName, envKey string, isOptional bool) (string, error) {
	if cmd.Flags().Changed(hostFlagName) {
		value, err := cmd.Flags().GetString(hostFlagName)
		if err != nil {
			return "", fmt.Errorf(hostFlagName+" flag not found: %s", err)
		}

		return value, nil
	}

	value, isSet := os.LookupEnv(envKey)

	if isOptional || isSet {
		return value, nil
	}

	return "", errors.New("Neither " + hostFlagName + " (command line flag) nor " + envKey +
		" (environment variable) have been set.")
}

func getWebhookURLs(cmd *cobra.Command, webhookURLsFromCmdLine []string) ([]string, error) {
	if cmd.Flags().Changed(agentWebhookFlagName) {
		return webhookURLsFromCmdLine, nil
	}

	webhookURLsCSV, isSet := os.LookupEnv(agentWebhookEnvKey)
	webhookURLs := strings.Split(webhookURLsCSV, ",")

	if isSet {
		return webhookURLs, nil
	}

	return nil, fmt.Errorf("agent webhook URL not set. " +
		"It must be set via either command line or environment variable")
}

func startAgent(parameters *agentParameters) error {
	if parameters.host == "" {
		return errMissingHost
	}

	if parameters.inboundHostInternal == "" {
		return errMissingInboundHost
	}

	var opts []aries.Option
	opts = append(opts, defaults.WithInboundHTTPAddr(parameters.inboundHostInternal, parameters.inboundHostExternal))

	if parameters.dbPath != "" {
		opts = append(opts, defaults.WithStorePath(parameters.dbPath))
	}

	framework, err := aries.New(opts...)
	if err != nil {
		return fmt.Errorf("failed to start aries agentd on port [%s], failed to initialize framework :  %w",
			parameters.host, err)
	}

	ctx, err := framework.Context()
	if err != nil {
		return fmt.Errorf("failed to start aries agentd on port [%s], failed to get aries context : %w",
			parameters.host, err)
	}

	// get all HTTP REST API handlers available for controller API
	restService, err := restapi.New(ctx, restapi.WithWebhookURLs(parameters.webhookURLs...),
		restapi.WithDefaultLabel(parameters.defaultLabel))
	if err != nil {
		return fmt.Errorf("failed to start aries agentd on port [%s], failed to get rest service api :  %w",
			parameters.host, err)
	}

	handlers := restService.GetOperations()
	router := mux.NewRouter()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logger.Infof("Starting aries agentd on host [%s]", parameters.host)
	// start server on given port and serve using given handlers
	handler := cors.Default().Handler(router)

	err = parameters.server.ListenAndServe(parameters.host, handler)
	if err != nil {
		return fmt.Errorf("failed to start aries agentd on port [%s], cause:  %w", parameters.host, err)
	}

	return nil
}
