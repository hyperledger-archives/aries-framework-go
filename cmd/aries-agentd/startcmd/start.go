/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	"github.com/hyperledger/aries-framework-go/pkg/restapi"
)

const (
	// AgentHostFlagName is the flag name for the agent host command line argument.
	AgentHostFlagName = "api-host"

	// AgentHostFlagShorthand is the flag shorthand name for the agent host command line argument.
	AgentHostFlagShorthand = "a"

	// AgentHostFlagUsage is the usage text for the host command line argument.
	AgentHostFlagUsage = "Host Name:Port"

	// AgentInboundHostFlagName is the flag name for the agent inbound host command line argument.
	AgentInboundHostFlagName = "inbound-host"

	// AgentInboundHostFlagShorthand is the flag shorthand for the agent inbound host command line argument.
	AgentInboundHostFlagShorthand = "i"

	// AgentInboundHostFlagUsage is the usage text for the agent inbound host command line argument.
	AgentInboundHostFlagUsage = "Inbound Host Name:Port. This is used internally to start the inbound server."

	agentInboundHostExternalFlagName = "inbound-host-external"

	agentInboundHostExternalFlagShorthand = "e"

	agentInboundHostExternalFlagUsage = "Inbound Host External Name:Port." +
		" This is the URL for the inbound server as seen externally." +
		" If not provided, then the internal inbound host will be used here."

	// AgentDBPathFlagName is the flag name for the database path command line argument.
	AgentDBPathFlagName = "db-path"

	// AgentDBPathFlagShorthand is the flag shorthand name for the database path command line argument.
	AgentDBPathFlagShorthand = "d"

	// AgentDBPathFlagUsage is the flag usage text for the database path command line argument.
	AgentDBPathFlagUsage = "Path to database"

	// AgentWebhookFlagName is the flag name for the webhook command line argument.
	AgentWebhookFlagName = "webhook-url"

	agentWebhookFlagShorthand = "w"

	agentWebhookFlagUsage = "URL to send notifications to." +
		" This flag can be repeated, allowing for multiple listeners."
)

// ErrMissingHost is the error when the user provides a blank host argument.
var ErrMissingHost = errors.New("unable to start aries agentd, host not provided")

// ErrMissingInboundHost is the error when the user provides a blank inbound host argument.
var ErrMissingInboundHost = errors.New("unable to start aries agentd, HTTP Inbound transport host not provided")

var logger = log.New("aries-framework/agentd")

type agentParameters struct {
	server                                                 server
	host, inboundHostInternal, inboundHostExternal, dbPath string
	webhookURLs                                            []string
}

type server interface {
	ListenAndServe(host string, router *mux.Router) error
}

// HTTPServer represents an actual server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host string, router *mux.Router) error {
	return http.ListenAndServe(host, router)
}

// Cmd returns the Cobra start command.
func Cmd(server server) (*cobra.Command, error) {
	var webhookURLs []string
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start an agent",
		Long:  `Start an Aries agent controller`,

		RunE: func(cmd *cobra.Command, args []string) error {
			host, err := cmd.Flags().GetString(AgentHostFlagName)
			if err != nil {
				return fmt.Errorf("agent host flag not found: %s", err)
			}

			inboundHost, err := cmd.Flags().GetString(AgentInboundHostFlagName)
			if err != nil {
				return fmt.Errorf("agent inbound host flag not found: %s", err)
			}

			dbPath, err := cmd.Flags().GetString(AgentDBPathFlagName)
			if err != nil {
				return fmt.Errorf("agent DB path flag not found: %s", err)
			}

			inboundHostExternal, err := cmd.Flags().GetString(agentInboundHostExternalFlagName)
			if err != nil {
				return fmt.Errorf("agent DB path flag not found: %s", err)
			}

			parameters := &agentParameters{server, host, inboundHost,
				inboundHostExternal, dbPath, webhookURLs}
			err = startAgent(parameters)
			if err != nil {
				return fmt.Errorf("unable to start agent: %s", err)
			}

			return nil
		},
	}

	err := createFlags(startCmd, &webhookURLs)
	if err != nil {
		return nil, err
	}

	return startCmd, nil
}

func createFlags(startCmd *cobra.Command, webhookURLs *[]string) error {
	startCmd.Flags().StringP(AgentHostFlagName, AgentHostFlagShorthand, "", AgentHostFlagUsage)
	err := startCmd.MarkFlagRequired(AgentHostFlagName)
	if err != nil {
		return fmt.Errorf("tried to mark host flag as required but it was not found: %s", err)
	}

	startCmd.Flags().StringP(AgentInboundHostFlagName, AgentInboundHostFlagShorthand, "", AgentInboundHostFlagUsage)
	err = startCmd.MarkFlagRequired(AgentInboundHostFlagName)
	if err != nil {
		return fmt.Errorf("tried to mark inbound host flag as required but it was not found: %s", err)
	}

	startCmd.Flags().StringP(AgentDBPathFlagName, AgentDBPathFlagShorthand, "", AgentDBPathFlagUsage)
	err = startCmd.MarkFlagRequired(AgentDBPathFlagName)
	if err != nil {
		return fmt.Errorf("tried to mark DB path flag as required but it was not found: %s", err)
	}

	startCmd.Flags().StringSliceVarP(webhookURLs, AgentWebhookFlagName, agentWebhookFlagShorthand, []string{},
		agentWebhookFlagUsage)
	err = startCmd.MarkFlagRequired(AgentWebhookFlagName)
	if err != nil {
		return fmt.Errorf("tried to mark agent webhook host flag as required but it was not found: %s", err)
	}

	startCmd.Flags().StringP(agentInboundHostExternalFlagName, agentInboundHostExternalFlagShorthand,
		"", agentInboundHostExternalFlagUsage)

	return nil
}

func startAgent(parameters *agentParameters) error {
	if parameters.host == "" {
		return ErrMissingHost
	}

	if parameters.inboundHostInternal == "" {
		return ErrMissingInboundHost
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
	restService, err := restapi.New(ctx, restapi.WithWebhookURLs(parameters.webhookURLs...))
	if err != nil {
		return fmt.Errorf("failed to start aries agentd on port [%s], failed to get rest service api :  %w",
			parameters.host, err)
	}
	handlers := restService.GetOperations()

	// register handlers
	router := mux.NewRouter()
	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logger.Infof("Starting aries agentd on host [%s]", parameters.host)

	// start server on given port and serve using given handlers
	err = parameters.server.ListenAndServe(parameters.host, router)
	if err != nil {
		return fmt.Errorf("failed to start aries agentd on port [%s], cause:  %w", parameters.host, err)
	}

	return nil
}
