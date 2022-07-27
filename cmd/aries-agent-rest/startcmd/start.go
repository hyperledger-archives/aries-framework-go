/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/spf13/cobra"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/postgresql"
	"github.com/hyperledger/aries-framework-go/component/storage/leveldb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
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
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// api host flag.
	agentHostFlagName      = "api-host"
	agentHostEnvKey        = "ARIESD_API_HOST"
	agentHostFlagShorthand = "a"
	agentHostFlagUsage     = "Host Name:Port." +
		" Alternatively, this can be set with the following environment variable: " + agentHostEnvKey

	// api token flag.
	agentTokenFlagName      = "api-token"
	agentTokenEnvKey        = "ARIESD_API_TOKEN" // nolint:gosec
	agentTokenFlagShorthand = "t"
	agentTokenFlagUsage     = "Check for bearer token in the authorization header (optional)." +
		" Alternatively, this can be set with the following environment variable: " + agentTokenEnvKey

	databaseTypeFlagName      = "database-type"
	databaseTypeEnvKey        = "ARIESD_DATABASE_TYPE"
	databaseTypeFlagShorthand = "q"
	databaseTypeFlagUsage     = "The type of database to use for everything except key storage. " +
		"Supported options: mem, leveldb, couchdb, mongodb, mysql, postgresql. " +
		" Alternatively, this can be set with the following environment variable: " + databaseTypeEnvKey

	databasePrefixFlagName      = "database-prefix"
	databasePrefixEnvKey        = "ARIESD_DATABASE_PREFIX"
	databasePrefixFlagShorthand = "u"
	databasePrefixFlagUsage     = "An optional prefix to be used when creating and retrieving underlying databases. " +
		"Also you can use this variable for paths or connection strings as needed. " +
		" Alternatively, this can be set with the following environment variable: " + databasePrefixEnvKey

	databaseTimeoutFlagName  = "database-timeout"
	databaseTimeoutFlagUsage = "Total time in seconds to wait until the db is available before giving up." +
		" Default: " + databaseTimeoutDefault + " seconds." +
		" Alternatively, this can be set with the following environment variable: " + databaseTimeoutEnvKey
	databaseTimeoutEnvKey  = "ARIESD_DATABASE_TIMEOUT"
	databaseTimeoutDefault = "30"

	// webhook url flag.
	agentWebhookFlagName      = "webhook-url"
	agentWebhookEnvKey        = "ARIESD_WEBHOOK_URL"
	agentWebhookFlagShorthand = "w"
	agentWebhookFlagUsage     = "URL to send notifications to." +
		" This flag can be repeated, allowing for multiple listeners." +
		" Alternatively, this can be set with the following environment variable (in CSV format): " + agentWebhookEnvKey

	// default label flag.
	agentDefaultLabelFlagName      = "agent-default-label"
	agentDefaultLabelEnvKey        = "ARIESD_DEFAULT_LABEL"
	agentDefaultLabelFlagShorthand = "l"
	agentDefaultLabelFlagUsage     = "Default Label for this agent. Defaults to blank if not set." +
		" Alternatively, this can be set with the following environment variable: " + agentDefaultLabelEnvKey

	// log level.
	agentLogLevelFlagName  = "log-level"
	agentLogLevelEnvKey    = "ARIESD_LOG_LEVEL"
	agentLogLevelFlagUsage = "Log level." +
		" Possible values [INFO] [DEBUG] [ERROR] [WARNING] [CRITICAL] . Defaults to INFO if not set." +
		" Alternatively, this can be set with the following environment variable: " + agentLogLevelEnvKey

	// http resolver url flag.
	agentHTTPResolverFlagName      = "http-resolver-url"
	agentHTTPResolverEnvKey        = "ARIESD_HTTP_RESOLVER"
	agentHTTPResolverFlagShorthand = "r"
	agentHTTPResolverFlagUsage     = "HTTP binding DID resolver method and url. Values should be in `method@url` format." +
		" This flag can be repeated, allowing multiple http resolvers. Defaults to peer DID resolver if not set." +
		" Alternatively, this can be set with the following environment variable (in CSV format): " +
		agentHTTPResolverEnvKey

	// outbound transport flag.
	agentOutboundTransportFlagName      = "outbound-transport"
	agentOutboundTransportEnvKey        = "ARIESD_OUTBOUND_TRANSPORT"
	agentOutboundTransportFlagShorthand = "o"
	agentOutboundTransportFlagUsage     = "Outbound transport type." +
		" This flag can be repeated, allowing for multiple transports." +
		" Possible values [http] [ws]. Defaults to http if not set." +
		" Alternatively, this can be set with the following environment variable: " + agentOutboundTransportEnvKey

	agentTLSCertFileFlagName      = "tls-cert-file"
	agentTLSCertFileEnvKey        = "TLS_CERT_FILE"
	agentTLSCertFileFlagShorthand = "c"
	agentTLSCertFileFlagUsage     = "tls certificate file." +
		" Alternatively, this can be set with the following environment variable: " + agentTLSCertFileEnvKey

	agentTLSKeyFileFlagName      = "tls-key-file"
	agentTLSKeyFileEnvKey        = "TLS_KEY_FILE"
	agentTLSKeyFileFlagShorthand = "k"
	agentTLSKeyFileFlagUsage     = "tls key file." +
		" Alternatively, this can be set with the following environment variable: " + agentTLSKeyFileEnvKey

	// inbound host url flag.
	agentInboundHostFlagName      = "inbound-host"
	agentInboundHostEnvKey        = "ARIESD_INBOUND_HOST"
	agentInboundHostFlagShorthand = "i"
	agentInboundHostFlagUsage     = "Inbound Host Name:Port. This is used internally to start the inbound server." +
		" Values should be in `scheme@url` format." +
		" This flag can be repeated, allowing to configure multiple inbound transports." +
		" Alternatively, this can be set with the following environment variable: " + agentInboundHostEnvKey

	// inbound host external url flag.
	agentInboundHostExternalFlagName      = "inbound-host-external"
	agentInboundHostExternalEnvKey        = "ARIESD_INBOUND_HOST_EXTERNAL"
	agentInboundHostExternalFlagShorthand = "e"
	agentInboundHostExternalFlagUsage     = "Inbound Host External Name:Port and values should be in `scheme@url` format" +
		" This is the URL for the inbound server as seen externally." +
		" If not provided, then the internal inbound host will be used here." +
		" This flag can be repeated, allowing to configure multiple inbound transports." +
		" Alternatively, this can be set with the following environment variable: " + agentInboundHostExternalEnvKey

	// websocket read limit flag.
	agentWebSocketReadLimitFlagName  = "web-socket-read-limit"
	agentWebSocketReadLimitEnvKey    = "ARIESD_WEB_SOCKET_READ_LIMIT"
	agentWebSocketReadLimitFlagUsage = "WebSocket read limit sets the custom max number of bytes to" +
		" read for a single message when WebSocket transport is used. Defaults to 32kB." +
		" Alternatively, this can be set with the following environment variable: " + agentWebSocketReadLimitEnvKey

	// auto accept flag.
	agentAutoAcceptFlagName  = "auto-accept"
	agentAutoAcceptEnvKey    = "ARIESD_AUTO_ACCEPT"
	agentAutoAcceptFlagUsage = "Auto accept requests." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + agentAutoAcceptEnvKey

	// transport return route option flag.
	agentTransportReturnRouteFlagName  = "transport-return-route"
	agentTransportReturnRouteEnvKey    = "ARIESD_TRANSPORT_RETURN_ROUTE"
	agentTransportReturnRouteFlagUsage = "Transport Return Route option." +
		" Refer https://github.com/hyperledger/aries-framework-go/blob/8449c727c7c44f47ed7c9f10f35f0cd051dcb4e9/pkg/framework/aries/framework.go#L165-L168." + // nolint: lll
		" Alternatively, this can be set with the following environment variable: " + agentTransportReturnRouteEnvKey

	agentAutoExecuteRFC0593FlagName  = "rfc0593-auto-execute"
	agentAutoExecuteRFC0593EnvKey    = "ARIESD_RFC0593_AUTO_EXECUTE"
	agentAutoExecuteRFC0593FlagUsage = "Enables automatic execution of the issue-credential protocol with" +
		"RFC0593-compliant attachment formats. Default is false." +
		" Alternatively, this can be set with the following environment variable: " + agentAutoExecuteRFC0593EnvKey

	// remote JSON-LD context provider url flag.
	agentContextProviderFlagName  = "context-provider-url"
	agentContextProviderEnvKey    = "ARIESD_CONTEXT_PROVIDER_URL"
	agentContextProviderFlagUsage = "Remote context provider URL to get JSON-LD contexts from." +
		" This flag can be repeated, allowing setting up multiple context providers." +
		" Alternatively, this can be set with the following environment variable (in CSV format): " +
		agentContextProviderEnvKey

	// default verification key type flag.
	agentKeyTypeFlagName = "key-type"
	agentKeyTypeEnvKey   = "ARIESD_KEY_TYPE"
	agentKeyTypeUsage    = "Default key type supported by this agent." +
		" This flag sets the verification (and for DIDComm V1 encryption as well) key type used for key creation in the agent." + //nolint:lll
		" Alternatively, this can be set with the following environment variable: " +
		agentKeyTypeEnvKey

	// default key agreement type flag.
	agentKeyAgreementTypeFlagName = "key-agreement-type"
	agentKeyAgreementTypeEnvKey   = "ARIESD_KEY_AGREEMENT_TYPE"
	agentKeyAgreementTypeUsage    = "Default key agreement type supported by this agent." +
		" Default encryption (used in DIDComm V2) key type used for key agreement creation in the agent." +
		" Alternatively, this can be set with the following environment variable: " +
		agentKeyAgreementTypeEnvKey

	// media type profiles flag.
	agentMediaTypeProfilesFlagName = "media-type-profiles"
	agentMediaTypeProfilesEnvKey   = "ARIESD_MEDIA_TYPE_PROFILES"
	agentMediaTypeProfilesUsage    = "Media Type Profiles supported by this agent." +
		" This flag can be repeated, allowing setting up multiple profiles." +
		" Alternatively, this can be set with the following environment variable (in CSV format): " +
		agentMediaTypeProfilesEnvKey

	httpProtocol      = "http"
	websocketProtocol = "ws"

	databaseTypeMemOption        = "mem"
	databaseTypeLevelDBOption    = "leveldb"
	databaseTypeCouchDBOption    = "couchdb"
	databaseTypeMongoDBOption    = "mongodb"
	databaseTypeMySQLOption      = "mysql"
	databaseTypePostgreSQLOption = "postgresql"
)

var (
	errMissingHost = errors.New("host not provided")
	logger         = log.New("aries-framework/agent-rest")

	//nolint:gochecknoglobals
	keyTypes = map[string]kms.KeyType{
		"ed25519":           kms.ED25519Type,
		"ecdsap256ieee1363": kms.ECDSAP256TypeIEEEP1363,
		"ecdsap256der":      kms.ECDSAP256TypeDER,
		"ecdsap384ieee1363": kms.ECDSAP384TypeIEEEP1363,
		"ecdsap384der":      kms.ECDSAP384TypeDER,
		"ecdsap521ieee1363": kms.ECDSAP521TypeIEEEP1363,
		"ecdsap521der":      kms.ECDSAP521TypeDER,
	}

	//nolint:gochecknoglobals
	keyAgreementTypes = map[string]kms.KeyType{
		"x25519kw": kms.X25519ECDHKWType,
		"p256kw":   kms.NISTP256ECDHKWType,
		"p384kw":   kms.NISTP384ECDHKWType,
		"p521kw":   kms.NISTP521ECDHKWType,
	}
)

// AgentParameters represents the various options to run an Aries Agent.
type AgentParameters struct {
	server                                         server
	host, defaultLabel, transportReturnRoute       string
	tlsCertFile, tlsKeyFile                        string
	token, keyType, keyAgreementType               string
	webhookURLs, httpResolvers, outboundTransports []string
	inboundHostInternals, inboundHostExternals     []string
	websocketReadLimit                             int64
	contextProviderURLs, mediaTypeProfiles         []string
	autoAccept                                     bool
	msgHandler                                     command.MessageHandler
	dbParam                                        *dbParam
	autoExecuteRFC0593                             bool
}

type dbParam struct {
	dbType  string
	prefix  string
	timeout uint64
}

// nolint:gochecknoglobals
var supportedStorageProviders = map[string]func(prefix string) (storage.Provider, error){
	databaseTypeMemOption: func(_ string) (storage.Provider, error) { // nolint:unparam
		return mem.NewProvider(), nil
	},
	databaseTypeLevelDBOption: func(path string) (storage.Provider, error) { // nolint:unparam
		return leveldb.NewProvider(path), nil
	},
	databaseTypeCouchDBOption: func(hostURL string) (storage.Provider, error) {
		return couchdb.NewProvider(hostURL)
	},
	databaseTypeMongoDBOption: func(connectionString string) (storage.Provider, error) {
		return mongodb.NewProvider(connectionString)
	},
	databaseTypeMySQLOption: func(path string) (storage.Provider, error) {
		return mysql.NewProvider(path)
	},
	databaseTypePostgreSQLOption: func(connectionString string) (storage.Provider, error) {
		return postgresql.NewProvider(connectionString)
	},
}

type server interface {
	ListenAndServe(host string, router http.Handler, certFile, keyFile string) error
}

// HTTPServer represents an actual server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host string, router http.Handler, certFile, keyFile string) error {
	if certFile != "" && keyFile != "" {
		return http.ListenAndServeTLS(host, certFile, keyFile, router)
	}

	return http.ListenAndServe(host, router)
}

// Cmd returns the Cobra start command.
func Cmd(server server) (*cobra.Command, error) {
	startCmd := createStartCMD(server)

	createFlags(startCmd)

	return startCmd, nil
}

// NewAgentParameters constructs AgentParameters with the given cobra command.
func NewAgentParameters(server server, cmd *cobra.Command) (*AgentParameters, error) { //nolint: funlen,gocyclo
	// log level
	logLevel, err := getUserSetVar(cmd, agentLogLevelFlagName, agentLogLevelEnvKey, true)
	if err != nil {
		return nil, err
	}

	err = setLogLevel(logLevel)
	if err != nil {
		return nil, err
	}

	host, err := getUserSetVar(cmd, agentHostFlagName, agentHostEnvKey, false)
	if err != nil {
		return nil, err
	}

	token, err := getUserSetVar(cmd, agentTokenFlagName, agentTokenEnvKey, true)
	if err != nil {
		return nil, err
	}

	inboundHosts, err := getUserSetVars(cmd, agentInboundHostFlagName, agentInboundHostEnvKey, true)
	if err != nil {
		return nil, err
	}

	inboundHostExternals, err := getUserSetVars(cmd, agentInboundHostExternalFlagName,
		agentInboundHostExternalEnvKey, true)
	if err != nil {
		return nil, err
	}

	websocketReadLimit, err := getWebSocketReadLimit(cmd)
	if err != nil {
		return nil, err
	}

	dbParam, err := getDBParam(cmd)
	if err != nil {
		return nil, err
	}

	defaultLabel, err := getUserSetVar(cmd, agentDefaultLabelFlagName, agentDefaultLabelEnvKey, true)
	if err != nil {
		return nil, err
	}

	autoAccept, err := getAutoAcceptValue(cmd)
	if err != nil {
		return nil, err
	}

	webhookURLs, err := getUserSetVars(cmd, agentWebhookFlagName, agentWebhookEnvKey, autoAccept)
	if err != nil {
		return nil, err
	}

	httpResolvers, err := getUserSetVars(cmd, agentHTTPResolverFlagName, agentHTTPResolverEnvKey, true)
	if err != nil {
		return nil, err
	}

	outboundTransports, err := getUserSetVars(cmd, agentOutboundTransportFlagName,
		agentOutboundTransportEnvKey, true)
	if err != nil {
		return nil, err
	}

	transportReturnRoute, err := getUserSetVar(cmd, agentTransportReturnRouteFlagName,
		agentTransportReturnRouteEnvKey, true)
	if err != nil {
		return nil, err
	}

	contextProviderURLs, err := getUserSetVars(cmd, agentContextProviderFlagName, agentContextProviderEnvKey, true)
	if err != nil {
		return nil, err
	}

	autoExecuteRFC0593, err := getAutoExecuteRFC0593(cmd)
	if err != nil {
		return nil, err
	}

	tlsCertFile, err := getUserSetVar(cmd, agentTLSCertFileFlagName, agentTLSCertFileEnvKey, true)
	if err != nil {
		return nil, err
	}

	tlsKeyFile, err := getUserSetVar(cmd, agentTLSKeyFileFlagName, agentTLSKeyFileEnvKey, true)
	if err != nil {
		return nil, err
	}

	keyType, err := getUserSetVar(cmd, agentKeyTypeFlagName, agentKeyTypeEnvKey, true)
	if err != nil {
		return nil, err
	}

	keyAgreementType, err := getUserSetVar(cmd, agentKeyAgreementTypeFlagName, agentKeyAgreementTypeEnvKey, true)
	if err != nil {
		return nil, err
	}

	mediaTypeProfiles, err := getUserSetVars(cmd, agentMediaTypeProfilesFlagName, agentMediaTypeProfilesEnvKey, true)
	if err != nil {
		return nil, err
	}

	parameters := &AgentParameters{
		server:               server,
		host:                 host,
		token:                token,
		inboundHostInternals: inboundHosts,
		inboundHostExternals: inboundHostExternals,
		websocketReadLimit:   websocketReadLimit,
		dbParam:              dbParam,
		defaultLabel:         defaultLabel,
		webhookURLs:          webhookURLs,
		httpResolvers:        httpResolvers,
		outboundTransports:   outboundTransports,
		autoAccept:           autoAccept,
		transportReturnRoute: transportReturnRoute,
		contextProviderURLs:  contextProviderURLs,
		tlsCertFile:          tlsCertFile,
		tlsKeyFile:           tlsKeyFile,
		autoExecuteRFC0593:   autoExecuteRFC0593,
		keyType:              keyType,
		keyAgreementType:     keyAgreementType,
		mediaTypeProfiles:    mediaTypeProfiles,
	}

	return parameters, nil
}

func createStartCMD(server server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start an agent",
		Long:  `Start an Aries agent controller`,
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := NewAgentParameters(server, cmd)
			if err != nil {
				return err
			}
			return startAgent(parameters)
		},
	}
}

func getDBParam(cmd *cobra.Command) (*dbParam, error) {
	dbParam := &dbParam{}

	var err error

	dbParam.dbType, err = getUserSetVar(cmd, databaseTypeFlagName, databaseTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	dbParam.prefix, err = getUserSetVar(cmd, databasePrefixFlagName, databasePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	dbTimeout, err := getUserSetVar(cmd, databaseTimeoutFlagName, databaseTimeoutEnvKey, true)
	if err != nil {
		return nil, err
	}

	if dbTimeout == "" || dbTimeout == "0" {
		dbTimeout = databaseTimeoutDefault
	}

	t, err := strconv.Atoi(dbTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse db timeout %s: %w", dbTimeout, err)
	}

	dbParam.timeout = uint64(t)

	return dbParam, nil
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

func getAutoExecuteRFC0593(cmd *cobra.Command) (bool, error) {
	autoExecuteRFC0593Str, err := getUserSetVar(cmd, agentAutoExecuteRFC0593FlagName,
		agentAutoExecuteRFC0593EnvKey, true)
	if err != nil {
		return false, err
	}

	if autoExecuteRFC0593Str == "" {
		return false, nil
	}

	return strconv.ParseBool(autoExecuteRFC0593Str)
}

func getWebSocketReadLimit(cmd *cobra.Command) (int64, error) {
	readLimitVal, err := getUserSetVar(cmd, agentWebSocketReadLimitFlagName,
		agentWebSocketReadLimitEnvKey, true)
	if err != nil {
		return 0, err
	}

	var readLimit int64

	if readLimitVal != "" {
		readLimit, err = strconv.ParseInt(readLimitVal, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse web socket read limit %s: %w", readLimitVal, err)
		}
	}

	return readLimit, nil
}

//nolint:funlen
func createFlags(startCmd *cobra.Command) {
	// agent host flag
	startCmd.Flags().StringP(agentHostFlagName, agentHostFlagShorthand, "", agentHostFlagUsage)

	// agent token flag
	startCmd.Flags().StringP(agentTokenFlagName, agentTokenFlagShorthand, "", agentTokenFlagUsage)

	// inbound host flag
	startCmd.Flags().StringSliceP(agentInboundHostFlagName, agentInboundHostFlagShorthand, []string{},
		agentInboundHostFlagUsage)

	// inbound external host flag
	startCmd.Flags().StringSliceP(agentInboundHostExternalFlagName, agentInboundHostExternalFlagShorthand,
		[]string{}, agentInboundHostExternalFlagUsage)

	// websocket read limit flag
	startCmd.Flags().StringP(agentWebSocketReadLimitFlagName, "", "", agentWebSocketReadLimitFlagUsage)

	// db type
	startCmd.Flags().StringP(databaseTypeFlagName, databaseTypeFlagShorthand, "", databaseTypeFlagUsage)

	// db prefix
	startCmd.Flags().StringP(databasePrefixFlagName, databasePrefixFlagShorthand, "", databasePrefixFlagUsage)

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

	// remote JSON-LD context provider url flag
	startCmd.Flags().StringSliceP(agentContextProviderFlagName, "", []string{}, agentContextProviderFlagUsage)

	startCmd.Flags().StringP(agentAutoExecuteRFC0593FlagName, "", "", agentAutoExecuteRFC0593FlagUsage)

	// tls cert file
	startCmd.Flags().StringP(agentTLSCertFileFlagName,
		agentTLSCertFileFlagShorthand, "", agentTLSCertFileFlagUsage)

	// tls key file
	startCmd.Flags().StringP(agentTLSKeyFileFlagName,
		agentTLSKeyFileFlagShorthand, "", agentTLSKeyFileFlagUsage)

	// db timeout
	startCmd.Flags().StringP(databaseTimeoutFlagName, "", "", databaseTimeoutFlagUsage)

	startCmd.Flags().StringP(agentKeyTypeFlagName, "", "", agentKeyTypeUsage)

	startCmd.Flags().StringP(agentKeyAgreementTypeFlagName, "", "", agentKeyAgreementTypeUsage)

	startCmd.Flags().StringSliceP(agentMediaTypeProfilesFlagName, "", []string{}, agentMediaTypeProfilesUsage)
}

func getUserSetVar(cmd *cobra.Command, flagName, envKey string, isOptional bool) (string, error) {
	if cmd != nil && cmd.Flags().Changed(flagName) {
		value, err := cmd.Flags().GetString(flagName)
		if err != nil {
			return "", fmt.Errorf(flagName+" flag not found: %s", err)
		}

		return value, nil
	}

	value, isSet := os.LookupEnv(envKey)

	if isOptional || isSet {
		return value, nil
	}

	return "", errors.New("Neither " + flagName + " (command line flag) nor " + envKey +
		" (environment variable) have been set.")
}

func getUserSetVars(cmd *cobra.Command, flagName, envKey string, isOptional bool) ([]string, error) {
	if cmd != nil && cmd.Flags().Changed(flagName) {
		value, err := cmd.Flags().GetStringSlice(flagName)
		if err != nil {
			return nil, fmt.Errorf(flagName+" flag not found: %s", err)
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
		"It must be set via either command line or environment variable", flagName)
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

			httpVDR, err := httpbinding.New(r[1],
				httpbinding.WithAccept(func(method string) bool { return method == r[0] }))
			if err != nil {
				return nil, fmt.Errorf("failed to setup http resolver :  %w", err)
			}

			opts = append(opts, aries.WithVDR(httpVDR))
		}
	}

	return opts, nil
}

func getOutboundTransportOpts(outboundTransports []string, readLimit int64) ([]aries.Option, error) {
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
			var outboundOpts []ws.OutboundClientOpt

			if readLimit > 0 {
				outboundOpts = append(outboundOpts, ws.WithOutboundReadLimit(readLimit))
			}

			transports = append(transports, ws.NewOutbound(outboundOpts...))
		default:
			return nil, fmt.Errorf("outbound transport [%s] not supported", outboundTransport)
		}
	}

	if len(transports) > 0 {
		opts = append(opts, aries.WithOutboundTransports(transports...))
	}

	return opts, nil
}

func getInboundTransportOpts(inboundHostInternals, inboundHostExternals []string, certFile,
	keyFile string, readLimit int64) ([]aries.Option, error) {
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
			opts = append(opts, defaults.WithInboundHTTPAddr(host, externalHost[scheme], certFile, keyFile))
		case websocketProtocol:
			opts = append(opts, defaults.WithInboundWSAddr(host, externalHost[scheme], certFile, keyFile, readLimit))
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

func validateAuthorizationBearerToken(w http.ResponseWriter, r *http.Request, token string) bool {
	actHdr := r.Header.Get("Authorization")
	expHdr := "Bearer " + token

	if subtle.ConstantTimeCompare([]byte(actHdr), []byte(expHdr)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorised.\n")) // nolint:gosec,errcheck

		return false
	}

	return true
}

func authorizationMiddleware(token string) mux.MiddlewareFunc {
	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if validateAuthorizationBearerToken(w, r, token) {
				next.ServeHTTP(w, r)
			}
		})
	}

	return middleware
}

// NewRouter returns a Router for the Aries Agent.
func (parameters *AgentParameters) NewRouter() (*mux.Router, error) {
	if parameters.host == "" {
		return nil, errMissingHost
	}

	// set message handler
	parameters.msgHandler = msghandler.NewRegistrar()

	ctx, err := createAriesAgent(parameters)
	if err != nil {
		return nil, err
	}

	// get all HTTP REST API handlers available for controller API
	handlers, err := controller.GetRESTHandlers(ctx, controller.WithWebhookURLs(parameters.webhookURLs...),
		controller.WithDefaultLabel(parameters.defaultLabel), controller.WithAutoAccept(parameters.autoAccept),
		controller.WithMessageHandler(parameters.msgHandler),
		controller.WithAutoExecuteRFC0593(parameters.autoExecuteRFC0593))
	if err != nil {
		return nil, fmt.Errorf("failed to start aries agent rest on port [%s], failed to get rest service api :  %w",
			parameters.host, err)
	}

	router := mux.NewRouter()

	if parameters.token != "" {
		router.Use(authorizationMiddleware(parameters.token))
	}

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	return router, nil
}

func startAgent(parameters *AgentParameters) error {
	logger.Infof("Starting aries agent rest on host [%s]", parameters.host)

	router, err := parameters.NewRouter()
	if err != nil {
		return err
	}

	// start server on given port and serve using given handlers
	handler := cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodHead},
			AllowedHeaders: []string{"Origin", "Accept", "Content-Type", "X-Requested-With", "Authorization"},
		},
	).Handler(router)

	err = parameters.server.ListenAndServe(parameters.host, handler, parameters.tlsCertFile, parameters.tlsKeyFile)
	if err != nil {
		return fmt.Errorf("failed to start aries agent rest on port [%s], cause:  %w", parameters.host, err)
	}

	return nil
}

//nolint:funlen,gocyclo
func createAriesAgent(parameters *AgentParameters) (*context.Provider, error) {
	var opts []aries.Option

	storePro, err := createStoreProviders(parameters)
	if err != nil {
		return nil, err
	}

	opts = append(opts, aries.WithStoreProvider(storePro))

	if parameters.transportReturnRoute != "" {
		opts = append(opts, aries.WithTransportReturnRoute(parameters.transportReturnRoute))
	}

	inboundTransportOpt, err := getInboundTransportOpts(parameters.inboundHostInternals,
		parameters.inboundHostExternals, parameters.tlsCertFile, parameters.tlsKeyFile,
		parameters.websocketReadLimit)
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

	outboundTransportOpts, err := getOutboundTransportOpts(parameters.outboundTransports, parameters.websocketReadLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to start aries agent rest on port [%s], failed to outbound transport opts : %w",
			parameters.host, err)
	}

	opts = append(opts, outboundTransportOpts...)
	opts = append(opts, aries.WithMessageServiceProvider(parameters.msgHandler))

	if len(parameters.contextProviderURLs) > 0 {
		opts = append(opts, aries.WithJSONLDContextProviderURL(parameters.contextProviderURLs...))
	}

	if kt, ok := keyTypes[parameters.keyType]; ok {
		opts = append(opts, aries.WithKeyType(kt))
	}

	if kat, ok := keyAgreementTypes[parameters.keyAgreementType]; ok {
		opts = append(opts, aries.WithKeyAgreementType(kat))
	}

	if len(parameters.mediaTypeProfiles) > 0 {
		opts = append(opts, aries.WithMediaTypeProfiles(parameters.mediaTypeProfiles))
	}

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

func createStoreProviders(parameters *AgentParameters) (storage.Provider, error) {
	provider, supported := supportedStorageProviders[parameters.dbParam.dbType]
	if !supported {
		return nil, fmt.Errorf("key database type not set to a valid type." +
			" run start --help to see the available options")
	}

	var store storage.Provider

	err := backoff.RetryNotify(
		func() error {
			var openErr error
			store, openErr = provider(parameters.dbParam.prefix)
			return openErr
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), parameters.dbParam.timeout),
		func(retryErr error, t time.Duration) {
			logger.Warnf(
				"failed to connect to storage, will sleep for %s before trying again : %s\n",
				t, retryErr)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to storage at %s : %w", parameters.dbParam.prefix, err)
	}

	return store, nil
}
