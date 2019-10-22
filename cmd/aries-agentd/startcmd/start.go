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
	AgentInboundHostFlagUsage = "Inbound Host Name:Port"

	// AgentDBPathFlagName is the flag name for the database path command line argument.
	AgentDBPathFlagName = "db-path"

	// AgentDBPathFlagShorthand is the flag shorthand name for the database path command line argument.
	AgentDBPathFlagShorthand = "d"

	// AgentDBPathFlagUsage is the flag usage text for the database path command line argument.
	AgentDBPathFlagUsage = "Path to database"

	// AgentWebhookFlagName is the flag name for the webhook command line argument.
	AgentWebhookFlagName = "webhook-url"

	// AgentWebhookFlagShorthand is the flag shorthand name for the webhook command line argument.
	AgentWebhookFlagShorthand = "w"

	// AgentWebhookFlagUsage is the flag usage text for the webhook command line argument.
	AgentWebhookFlagUsage = "URL to send notifications to." +
		" This flag can be repeated, allowing for multiple listeners."
)

// ErrMissingHost is the error when the user provides a blank host argument.
var ErrMissingHost = errors.New("unable to start aries agentd, host not provided")

// ErrMissingInboundHost is the error when the user provides a blank inbound host argument.
var ErrMissingInboundHost = errors.New("unable to start aries agentd, HTTP Inbound transport host not provided")

var logger = log.New("aries-framework/agentd")

type agentParameters struct {
	server                    server
	host, inboundHost, dbPath string
	webhookURLs               []string
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

			parameters := &agentParameters{server, host, inboundHost, dbPath, webhookURLs}
			err = startAgent(parameters)
			if err != nil {
				return fmt.Errorf("unable to start agent: %s", err)
			}

			return nil
		},
	}
	startCmd.Flags().StringP(AgentHostFlagName, AgentHostFlagShorthand, "", AgentHostFlagUsage)
	err := startCmd.MarkFlagRequired(AgentHostFlagName)
	if err != nil {
		return nil, fmt.Errorf("tried to mark host flag as required but it was not found: %s", err)
	}

	startCmd.Flags().StringP(AgentInboundHostFlagName, AgentInboundHostFlagShorthand, "", AgentInboundHostFlagUsage)
	err = startCmd.MarkFlagRequired(AgentInboundHostFlagName)
	if err != nil {
		return nil, fmt.Errorf("tried to mark inbound host flag as required but it was not found: %s", err)
	}
	startCmd.Flags().StringP(AgentDBPathFlagName, AgentDBPathFlagShorthand, "", AgentDBPathFlagUsage)
	err = startCmd.MarkFlagRequired(AgentDBPathFlagName)
	if err != nil {
		return nil, fmt.Errorf("tried to mark DB path flag as required but it was not found: %s", err)
	}

	startCmd.Flags().StringSliceVarP(&webhookURLs, AgentWebhookFlagName, AgentWebhookFlagShorthand, []string{},
		AgentWebhookFlagUsage)
	err = startCmd.MarkFlagRequired(AgentWebhookFlagName)
	if err != nil {
		return nil, fmt.Errorf("tried to mark agent webhook host flag as required but it was not found: %s", err)
	}

	return startCmd, nil
}

func startAgent(parameters *agentParameters) error {
	if parameters.host == "" {
		return ErrMissingHost
	}

	if parameters.inboundHost == "" {
		return ErrMissingInboundHost
	}
	var opts []aries.Option
	opts = append(opts, defaults.WithInboundHTTPAddr(parameters.inboundHost))

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

	// Start controller server. For now, starting controller service inside agent and webhookURL is
	// used as the url of the controller server. Added here, as this is a reference implementation
	// and not actually part of the framework.
	startController(parameters.webhookURLs)

	// get all HTTP REST API handlers available for controller API
	restService, err := restapi.New(ctx, parameters.webhookURLs)
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

// startController starts the controller/webhook server.
func startController(webhookURLs []string) {
	if len(webhookURLs) == 0 {
		logger.Infof("Controller hot not provided")
		return
	}

	// Assumption : Get the url for reference controller directly from webhookURLs.
	webhookURL := webhookURLs[0]

	// register handlers
	router := mux.NewRouter()

	// handler for connections
	router.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		logger.Infof("received connection message")
		// TODO https://github.com/hyperledger/aries-framework-go/issues/542 Process "/connections"
		w.WriteHeader(http.StatusNotImplemented)
	}).Methods(http.MethodPost)

	// handler for basic messages
	router.HandleFunc("/basicmessages", func(w http.ResponseWriter, r *http.Request) {
		logger.Infof("received basicmessages")
		// TODO https://github.com/hyperledger/aries-framework-go/issues/543 Controller - Process "/basicmessages"
		w.WriteHeader(http.StatusNotImplemented)
	}).Methods(http.MethodPost)

	go func() {
		if err := http.ListenAndServe(webhookURL, router); err != http.ErrServerClosed {
			logger.Fatalf("HTTP Controller start with address [%s] failed, cause:  %s", webhookURL, err)
		}
	}()
}
