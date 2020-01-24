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
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/spf13/cobra"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/ws"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/restapi"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/httpbinding"
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

	agentHTTPResolverFlagName = "http-resolver-url"

	agentHTTPResolverFlagShorthand = "r"

	agentHTTPResolverFlagUsage = "HTTP binding DID resolver method and url. Values should be in `method@url` format." +
		" This flag can be repeated, allowing multiple http resolvers. Defaults to peer DID resolver if not set." +
		" Alternatively, this can be set with the following environment variable (in CSV format): " +
		agentHTTPResolverEnvKey

	agentHTTPResolverEnvKey = "ARIESD_HTTP_RESOLVER"

	agentOutboundTransportFlagName = "outbound-transport"

	agentOutboundTransportFlagShorthand = "o"

	agentOutboundTransportFlagUsage = "Outbound transport type." +
		" This flag can be repeated, allowing for multiple transports." +
		" Possible values [http] [ws]. Defaults to http if not set." +
		" Alternatively, this can be set with the following environment variable: " + agentOutboundTransportEnvKey

	agentOutboundTransportEnvKey = "ARIESD_OUTBOUND_TRANSPORT"

	agentInboundTransportEnvKey = "ARIESD_INBOUND_TRANSPORT"

	agentInboundTransportFlagName = "inbound-transport"

	agentInboundTransportFlagShorthand = "b"

	agentInboundTransportFlagUsage = "Inbound transport type." +
		" Possible values [http] [ws]. Defaults to http if not set." +
		" Alternatively, this can be set with the following environment variable: " + agentInboundTransportEnvKey

	agentAutoAcceptEnvKey = "ARIESD_AUTO_ACCEPT"

	agentAutoAcceptFlagName = "auto-accept"

	agentAutoAcceptFlagUsage = "Auto accept requests." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + agentAutoAcceptEnvKey

	httpProtocol      = "http"
	websocketProtocol = "ws"
)

var errMissingHost = errors.New("host not provided")

var errMissingInboundHost = errors.New("HTTP Inbound transport host not provided")

var logger = log.New("aries-framework/agent-rest")

type agentParameters struct {
	server                                                                                 server
	host, inboundHostInternal, inboundHostExternal, dbPath, defaultLabel, inboundTransport string
	webhookURLs, httpResolvers, outboundTransports                                         []string
	autoAccept                                                                             bool
	msgHandler                                                                             operation.MessageHandler
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
	startCmd := createStartCMD(server)

	createFlags(startCmd)

	return startCmd, nil
}

func createStartCMD(server server) *cobra.Command { //nolint funlen gocyclo
	return &cobra.Command{
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

			autoAccept, err := getAutoAcceptValue(cmd)
			if err != nil {
				return err
			}

			webhookURLs, err := getUserSetVars(cmd, agentWebhookFlagName,
				agentWebhookEnvKey, autoAccept)
			if err != nil {
				return err
			}

			httpResolvers, err := getUserSetVars(cmd, agentHTTPResolverFlagName,
				agentHTTPResolverEnvKey, true)
			if err != nil {
				return err
			}

			outboundTransports, err := getUserSetVars(cmd, agentOutboundTransportFlagName,
				agentOutboundTransportEnvKey, true)
			if err != nil {
				return err
			}

			inboundTransport, err := getUserSetVar(cmd, agentInboundTransportFlagName, agentInboundTransportEnvKey, true)
			if err != nil {
				return err
			}

			parameters := &agentParameters{server: server, host: host, inboundHostInternal: inboundHost,
				inboundHostExternal: inboundHostExternal, dbPath: dbPath, defaultLabel: defaultLabel, webhookURLs: webhookURLs,
				httpResolvers: httpResolvers, outboundTransports: outboundTransports, inboundTransport: inboundTransport,
				autoAccept: autoAccept}
			return startAgent(parameters)
		},
	}
}

func getAutoAcceptValue(cmd *cobra.Command) (bool, error) {
	v, err := getUserSetVar(cmd, agentAutoAcceptFlagName, agentAutoAcceptEnvKey, true)
	if err != nil {
		return false, err
	}

	if v == "" {
		return false, nil
	}

	return strconv.ParseBool(v)
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(agentHostFlagName, agentHostFlagShorthand, "", agentHostFlagUsage)
	startCmd.Flags().StringP(agentInboundHostFlagName, agentInboundHostFlagShorthand, "", agentInboundHostFlagUsage)
	startCmd.Flags().StringP(agentDBPathFlagName, agentDBPathFlagShorthand, "", agentDBPathFlagUsage)
	startCmd.Flags().StringSliceP(agentWebhookFlagName, agentWebhookFlagShorthand, []string{},
		agentWebhookFlagUsage)
	startCmd.Flags().StringSliceP(agentHTTPResolverFlagName, agentHTTPResolverFlagShorthand, []string{},
		agentHTTPResolverFlagUsage)
	startCmd.Flags().StringP(agentInboundHostExternalFlagName, agentInboundHostExternalFlagShorthand,
		"", agentInboundHostExternalFlagUsage)
	startCmd.Flags().StringP(agentDefaultLabelFlagName, agentDefaultLabelFlagShorthand, "",
		agentDefaultLabelFlagUsage)
	startCmd.Flags().StringSliceP(
		agentOutboundTransportFlagName, agentOutboundTransportFlagShorthand, []string{},
		agentOutboundTransportFlagUsage)
	startCmd.Flags().StringP(agentInboundTransportFlagName, agentInboundTransportFlagShorthand, "",
		agentInboundTransportFlagUsage)
	startCmd.Flags().StringP(agentAutoAcceptFlagName, "", "",
		agentAutoAcceptFlagUsage)
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

func getUserSetVars(cmd *cobra.Command, hostFlagName,
	envKey string, isOptional bool) ([]string, error) {
	if cmd.Flags().Changed(hostFlagName) {
		value, err := cmd.Flags().GetStringSlice(hostFlagName)
		if err != nil {
			return nil, fmt.Errorf(hostFlagName+" flag not found: %s", err)
		}

		return value, nil
	}

	value, isSet := os.LookupEnv(envKey)

	var values []string

	if isSet {
		values = strings.Split(value, ",")
	}

	if isOptional || isSet {
		return values, nil
	}

	return nil, fmt.Errorf(" %s not set. "+
		"It must be set via either command line or environment variable", hostFlagName)
}

func getResolverOpts(httpResolvers []string) ([]aries.Option, error) {
	var opts []aries.Option

	const numPartsResolverOption = 2

	if len(httpResolvers) > 0 {
		for _, httpResolver := range httpResolvers {
			r := strings.Split(httpResolver, "@")
			if len(r) != numPartsResolverOption {
				return nil, fmt.Errorf("invalid http resolver options found")
			}

			httpVDRI, err := httpbinding.New(r[1],
				httpbinding.WithAccept(func(method string) bool { return method == r[0] }))

			if err != nil {
				return nil, fmt.Errorf("failed to setup http resolver :  %w", err)
			}

			opts = append(opts, aries.WithVDRI(httpVDRI))
		}
	}

	return opts, nil
}

func getOutboundTransportOpts(outboundTransports []string) ([]aries.Option, error) {
	var opts []aries.Option

	var transports []transport.OutboundTransport

	for _, outboundTransport := range outboundTransports {
		switch outboundTransport {
		case httpProtocol:
			outbound, err := arieshttp.NewOutbound(arieshttp.WithOutboundHTTPClient(&http.Client{}))
			if err != nil {
				return nil, fmt.Errorf("http outbound transport initialization failed: %w", err)
			}

			transports = append(transports, outbound)
		case websocketProtocol:
			transports = append(transports, ws.NewOutbound())
		default:
			return nil, fmt.Errorf("outbound transport [%s] not supported", outboundTransport)
		}
	}

	if len(transports) > 0 {
		opts = append(opts, aries.WithOutboundTransports(transports...))
	}

	return opts, nil
}

func getInboundTransportOpts(inboundTransport, inboundHostInternal, inboundHostExternal string) (aries.Option, error) {
	if inboundTransport == "" {
		inboundTransport = httpProtocol
	}

	switch inboundTransport {
	case httpProtocol:
		return defaults.WithInboundHTTPAddr(inboundHostInternal, inboundHostExternal), nil
	case websocketProtocol:
		return defaults.WithInboundWSAddr(inboundHostInternal, inboundHostExternal), nil
	default:
		return nil, fmt.Errorf("inbound transport [%s] not supported", inboundTransport)
	}
}

func startAgent(parameters *agentParameters) error {
	if parameters.host == "" {
		return errMissingHost
	}

	if parameters.inboundHostInternal == "" {
		return errMissingInboundHost
	}

	// set message handler
	parameters.msgHandler = msghandler.NewRegistrar()

	ctx, err := createAriesAgent(parameters)
	if err != nil {
		return err
	}

	// get all HTTP REST API handlers available for controller API
	restService, err := restapi.New(ctx, restapi.WithWebhookURLs(parameters.webhookURLs...),
		restapi.WithDefaultLabel(parameters.defaultLabel), restapi.WithAutoAccept(parameters.autoAccept),
		restapi.WithMessageHandler(parameters.msgHandler))
	if err != nil {
		return fmt.Errorf("failed to start aries agent rest on port [%s], failed to get rest service api :  %w",
			parameters.host, err)
	}

	handlers := restService.GetOperations()
	router := mux.NewRouter()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logger.Infof("Starting aries agent rest on host [%s]", parameters.host)
	// start server on given port and serve using given handlers
	handler := cors.Default().Handler(router)

	err = parameters.server.ListenAndServe(parameters.host, handler)
	if err != nil {
		return fmt.Errorf("failed to start aries agent rest on port [%s], cause:  %w", parameters.host, err)
	}

	return nil
}

func createAriesAgent(parameters *agentParameters) (*context.Provider, error) {
	var opts []aries.Option

	if parameters.dbPath != "" {
		opts = append(opts, defaults.WithStorePath(parameters.dbPath))
	}

	inboundTransportOpt, err := getInboundTransportOpts(parameters.inboundTransport,
		parameters.inboundHostInternal, parameters.inboundHostExternal)
	if err != nil {
		return nil, fmt.Errorf("failed to start aries agent rest on port [%s], failed to inbound tranpsort opt : %w",
			parameters.host, err)
	}

	opts = append(opts, inboundTransportOpt)

	resolverOpts, err := getResolverOpts(parameters.httpResolvers)
	if err != nil {
		return nil, fmt.Errorf("failed to start aries agent rest on port [%s], failed to resolver opts : %w",
			parameters.host, err)
	}

	opts = append(opts, resolverOpts...)

	outboundTransportOpts, err := getOutboundTransportOpts(parameters.outboundTransports)
	if err != nil {
		return nil, fmt.Errorf("failed to start aries agent rest on port [%s], failed to outbound transport opts : %w",
			parameters.host, err)
	}

	opts = append(opts, outboundTransportOpts...)
	opts = append(opts, aries.WithMessageServiceProvider(parameters.msgHandler))

	framework, err := aries.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to start aries agent rest on port [%s], failed to initialize framework :  %w",
			parameters.host, err)
	}

	ctx, err := framework.Context()
	if err != nil {
		return nil, fmt.Errorf("failed to start aries agent rest on port [%s], failed to get aries context : %w",
			parameters.host, err)
	}

	return ctx, nil
}
