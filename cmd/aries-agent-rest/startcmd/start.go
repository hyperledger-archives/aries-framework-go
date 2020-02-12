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
	"github.com/hyperledger/aries-framework-go/pkg/controller"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/ws"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/httpbinding"
)

const (
	// api host flag
	agentHostFlagName      = "api-host"
	agentHostEnvKey        = "ARIESD_API_HOST"
	agentHostFlagShorthand = "a"
	agentHostFlagUsage     = "Host Name:Port." +
		" Alternatively, this can be set with the following environment variable: " + agentHostEnvKey

	// db path flag
	agentDBPathFlagName      = "db-path"
	agentDBPathEnvKey        = "ARIESD_DB_PATH"
	agentDBPathFlagShorthand = "d"
	agentDBPathFlagUsage     = "Path to database." +
		" Alternatively, this can be set with the following environment variable: " + agentDBPathEnvKey

	// webhook url flag
	agentWebhookFlagName      = "webhook-url"
	agentWebhookEnvKey        = "ARIESD_WEBHOOK_URL"
	agentWebhookFlagShorthand = "w"
	agentWebhookFlagUsage     = "URL to send notifications to." +
		" This flag can be repeated, allowing for multiple listeners." +
		" Alternatively, this can be set with the following environment variable (in CSV format): " + agentWebhookEnvKey

	// default label flag
	agentDefaultLabelFlagName      = "agent-default-label"
	agentDefaultLabelEnvKey        = "ARIESD_DEFAULT_LABEL"
	agentDefaultLabelFlagShorthand = "l"
	agentDefaultLabelFlagUsage     = "Default Label for this agent. Defaults to blank if not set." +
		" Alternatively, this can be set with the following environment variable: " + agentDefaultLabelEnvKey

	// log level
	agentLogLevelFlagName  = "log-level"
	agentLogLevelEnvKey    = "ARIESD_LOG_LEVEL"
	agentLogLevelFlagUsage = "Log Level." +
		" Possible values [INFO] [DEBUG] [ERROR] [WARNING] [CRITICAL] . Defaults to INFO if not set." +
		" Alternatively, this can be set with the following environment variable (in CSV format): " + agentLogLevelEnvKey

	// http resolver url flag
	agentHTTPResolverFlagName      = "http-resolver-url"
	agentHTTPResolverEnvKey        = "ARIESD_HTTP_RESOLVER"
	agentHTTPResolverFlagShorthand = "r"
	agentHTTPResolverFlagUsage     = "HTTP binding DID resolver method and url. Values should be in `method@url` format." +
		" This flag can be repeated, allowing multiple http resolvers. Defaults to peer DID resolver if not set." +
		" Alternatively, this can be set with the following environment variable (in CSV format): " +
		agentHTTPResolverEnvKey

	// outbound transport flag
	agentOutboundTransportFlagName      = "outbound-transport"
	agentOutboundTransportEnvKey        = "ARIESD_OUTBOUND_TRANSPORT"
	agentOutboundTransportFlagShorthand = "o"
	agentOutboundTransportFlagUsage     = "Outbound transport type." +
		" This flag can be repeated, allowing for multiple transports." +
		" Possible values [http] [ws]. Defaults to http if not set." +
		" Alternatively, this can be set with the following environment variable: " + agentOutboundTransportEnvKey

	// inbound host url flag
	agentInboundHostFlagName      = "inbound-host"
	agentInboundHostEnvKey        = "ARIESD_INBOUND_HOST"
	agentInboundHostFlagShorthand = "i"
	agentInboundHostFlagUsage     = "Inbound Host Name:Port. This is used internally to start the inbound server." +
		" Values should be in `scheme@url` format." +
		" This flag can be repeated, allowing to configure multiple inbound transports." +
		" Alternatively, this can be set with the following environment variable: " + agentInboundHostEnvKey

	// inbound host external url flag
	agentInboundHostExternalFlagName      = "inbound-host-external"
	agentInboundHostExternalEnvKey        = "ARIESD_INBOUND_HOST_EXTERNAL"
	agentInboundHostExternalFlagShorthand = "e"
	agentInboundHostExternalFlagUsage     = "Inbound Host External Name:Port and values should be in `scheme@url` format" +
		" This is the URL for the inbound server as seen externally." +
		" If not provided, then the internal inbound host will be used here." +
		" This flag can be repeated, allowing to configure multiple inbound transports." +
		" Alternatively, this can be set with the following environment variable: " + agentInboundHostExternalEnvKey

	// auto accept flag
	agentAutoAcceptFlagName  = "auto-accept"
	agentAutoAcceptEnvKey    = "ARIESD_AUTO_ACCEPT"
	agentAutoAcceptFlagUsage = "Auto accept requests." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + agentAutoAcceptEnvKey

	// transport return route option flag
	agentTransportReturnRouteFlagName  = "transport-return-route"
	agentTransportReturnRouteEnvKey    = "ARIESD_TRANSPORT_RETURN_ROUTE"
	agentTransportReturnRouteFlagUsage = "Transport Return Route option." +
		" Refer https://github.com/hyperledger/aries-framework-go/blob/8449c727c7c44f47ed7c9f10f35f0cd051dcb4e9/pkg/framework/aries/framework.go#L165-L168." + // nolint lll
		" Alternatively, this can be set with the following environment variable: " + agentTransportReturnRouteEnvKey

	httpProtocol      = "http"
	websocketProtocol = "ws"
)

var errMissingHost = errors.New("host not provided")
var logger = log.New("aries-framework/agent-rest")

type agentParameters struct {
	server                                           server
	host, dbPath, defaultLabel, transportReturnRoute string
	webhookURLs, httpResolvers, outboundTransports   []string
	inboundHostInternals, inboundHostExternals       []string
	autoAccept                                       bool
	msgHandler                                       command.MessageHandler
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
			// log level
			logLevel, err := getUserSetVar(cmd, agentLogLevelFlagName, agentLogLevelEnvKey, true)
			if err != nil {
				return err
			}

			err = setLogLevel(logLevel)
			if err != nil {
				return err
			}

			host, err := getUserSetVar(cmd, agentHostFlagName, agentHostEnvKey, false)
			if err != nil {
				return err
			}

			inboundHosts, err := getUserSetVars(cmd, agentInboundHostFlagName, agentInboundHostEnvKey, true)
			if err != nil {
				return err
			}

			inboundHostExternals, err := getUserSetVars(cmd, agentInboundHostExternalFlagName,
				agentInboundHostExternalEnvKey, true)
			if err != nil {
				return err
			}

			dbPath, err := getUserSetVar(cmd, agentDBPathFlagName, agentDBPathEnvKey, false)
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

			webhookURLs, err := getUserSetVars(cmd, agentWebhookFlagName, agentWebhookEnvKey, autoAccept)
			if err != nil {
				return err
			}

			httpResolvers, err := getUserSetVars(cmd, agentHTTPResolverFlagName, agentHTTPResolverEnvKey, true)
			if err != nil {
				return err
			}

			outboundTransports, err := getUserSetVars(cmd, agentOutboundTransportFlagName,
				agentOutboundTransportEnvKey, true)
			if err != nil {
				return err
			}

			transportReturnRoute, err := getUserSetVar(cmd, agentTransportReturnRouteFlagName,
				agentTransportReturnRouteEnvKey, true)
			if err != nil {
				return err
			}

			parameters := &agentParameters{
				server:               server,
				host:                 host,
				inboundHostInternals: inboundHosts,
				inboundHostExternals: inboundHostExternals,
				dbPath:               dbPath,
				defaultLabel:         defaultLabel,
				webhookURLs:          webhookURLs,
				httpResolvers:        httpResolvers,
				outboundTransports:   outboundTransports,
				autoAccept:           autoAccept,
				transportReturnRoute: transportReturnRoute,
			}

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
	// agent host flag
	startCmd.Flags().StringP(agentHostFlagName, agentHostFlagShorthand, "", agentHostFlagUsage)

	// inbound host flag
	startCmd.Flags().StringSliceP(agentInboundHostFlagName, agentInboundHostFlagShorthand, []string{},
		agentInboundHostFlagUsage)

	// inbound external host flag
	startCmd.Flags().StringSliceP(agentInboundHostExternalFlagName, agentInboundHostExternalFlagShorthand,
		[]string{}, agentInboundHostExternalFlagUsage)

	// db path flag
	startCmd.Flags().StringP(agentDBPathFlagName, agentDBPathFlagShorthand, "", agentDBPathFlagUsage)

	// webhook url flag
	startCmd.Flags().StringSliceP(agentWebhookFlagName, agentWebhookFlagShorthand, []string{}, agentWebhookFlagUsage)

	// log level
	startCmd.Flags().StringP(agentLogLevelFlagName, "", "", agentLogLevelFlagUsage)

	// http resolver url flag
	startCmd.Flags().StringSliceP(agentHTTPResolverFlagName, agentHTTPResolverFlagShorthand, []string{},
		agentHTTPResolverFlagUsage)

	// agent default label flag
	startCmd.Flags().StringP(agentDefaultLabelFlagName, agentDefaultLabelFlagShorthand, "",
		agentDefaultLabelFlagUsage)

	// agent outbound transport flag
	startCmd.Flags().StringSliceP(agentOutboundTransportFlagName, agentOutboundTransportFlagShorthand, []string{},
		agentOutboundTransportFlagUsage)

	// auto accept flag
	startCmd.Flags().StringP(agentAutoAcceptFlagName, "", "", agentAutoAcceptFlagUsage)

	// transport return route option flag
	startCmd.Flags().StringP(agentTransportReturnRouteFlagName, "", "", agentTransportReturnRouteFlagUsage)
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

func getInboundTransportOpts(inboundHostInternals, inboundHostExternals []string) ([]aries.Option, error) {
	internalHost, err := getInboundSchemeToURLMap(inboundHostInternals)
	if err != nil {
		return nil, fmt.Errorf("inbound internal host : %w", err)
	}

	externalHost, err := getInboundSchemeToURLMap(inboundHostExternals)
	if err != nil {
		return nil, fmt.Errorf("inbound external host : %w", err)
	}

	var opts []aries.Option

	for scheme, host := range internalHost {
		switch scheme {
		case httpProtocol:
			opts = append(opts, defaults.WithInboundHTTPAddr(host, externalHost[scheme]))
		case websocketProtocol:
			opts = append(opts, defaults.WithInboundWSAddr(host, externalHost[scheme]))
		default:
			return nil, fmt.Errorf("inbound transport [%s] not supported", scheme)
		}
	}

	return opts, nil
}

func getInboundSchemeToURLMap(schemeHostStr []string) (map[string]string, error) {
	const validSliceLen = 2

	schemeHostMap := make(map[string]string)

	for _, schemeHost := range schemeHostStr {
		schemeHostSlice := strings.Split(schemeHost, "@")
		if len(schemeHostSlice) != validSliceLen {
			return nil, fmt.Errorf("invalid inbound host option: Use scheme@url to pass the option")
		}

		schemeHostMap[schemeHostSlice[0]] = schemeHostSlice[1]
	}

	return schemeHostMap, nil
}

func setLogLevel(logLevel string) error {
	if logLevel != "" {
		level, err := log.ParseLevel(logLevel)
		if err != nil {
			return fmt.Errorf("failed to parse log level '%s' : %w", logLevel, err)
		}

		log.SetLevel("", level)

		logger.Infof("logger level set to %s", logLevel)
	}

	return nil
}

func startAgent(parameters *agentParameters) error {
	if parameters.host == "" {
		return errMissingHost
	}

	// set message handler
	parameters.msgHandler = msghandler.NewRegistrar()

	ctx, err := createAriesAgent(parameters)
	if err != nil {
		return err
	}

	// get all HTTP REST API handlers available for controller API
	handlers, err := controller.GetRESTHandlers(ctx, controller.WithWebhookURLs(parameters.webhookURLs...),
		controller.WithDefaultLabel(parameters.defaultLabel), controller.WithAutoAccept(parameters.autoAccept),
		controller.WithMessageHandler(parameters.msgHandler))
	if err != nil {
		return fmt.Errorf("failed to start aries agent rest on port [%s], failed to get rest service api :  %w",
			parameters.host, err)
	}

	router := mux.NewRouter()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logger.Infof("Starting aries agent rest on host [%s]", parameters.host)
	// start server on given port and serve using given handlers
	handler := cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodHead},
		},
	).Handler(router)

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

	if parameters.transportReturnRoute != "" {
		opts = append(opts, aries.WithTransportReturnRoute(parameters.transportReturnRoute))
	}

	inboundTransportOpt, err := getInboundTransportOpts(parameters.inboundHostInternals,
		parameters.inboundHostExternals)
	if err != nil {
		return nil, fmt.Errorf("failed to start aries agent rest on port [%s], failed to inbound tranpsort opt : %w",
			parameters.host, err)
	}

	opts = append(opts, inboundTransportOpt...)

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
