/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

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

	// MissingHostErrorMessage is the error message shown when the user provides a blank host argument.
	MissingHostErrorMessage = "Unable to start aries agentd, host not provided"

	// MissingInboundHostErrorMessage is the error message shown when the user provides a blank inbound host argument.
	MissingInboundHostErrorMessage = "Unable to start aries agentd, HTTP Inbound transport host not provided"
)

var logger = log.New("aries-framework/agentd")

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

			err = startAgent(server, host, inboundHost, dbPath)
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

	return startCmd, nil
}

func startAgent(server server, host, inboundHost, dbPath string) error {
	if host == "" {
		return errors.New(strings.ToLower(MissingHostErrorMessage))
	}

	if inboundHost == "" {
		return errors.New(strings.ToLower(MissingInboundHostErrorMessage))
	}
	var opts []aries.Option
	opts = append(opts, defaults.WithInboundHTTPAddr(inboundHost))

	if dbPath != "" {
		opts = append(opts, defaults.WithStorePath(dbPath))
	}

	framework, err := aries.New(opts...)
	if err != nil {
		return fmt.Errorf("failed to start aries agentd on port [%s], failed to initialize framework :  %w", host, err)
	}

	ctx, err := framework.Context()
	if err != nil {
		return fmt.Errorf("failed to start aries agentd on port [%s], failed to get aries context : %w", host, err)
	}

	// get all HTTP REST API handlers available for controller A PI
	restService, err := restapi.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to start aries agentd on port [%s], failed to get rest service api :  %w", host, err)
	}
	handlers := restService.GetOperations()

	// register handlers
	router := mux.NewRouter()
	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logger.Infof("Starting aries agentd on host [%s]", host)

	// start server on given port and serve using given handlers
	err = server.ListenAndServe(host, router)
	if err != nil {
		return fmt.Errorf("failed to start aries agentd on port [%s], cause:  %w", host, err)
	}

	return nil
}
