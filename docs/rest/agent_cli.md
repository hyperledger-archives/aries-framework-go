# Run the agent as a binary

## Build the Agent

The agent can be built from within the `cmd/aries-agent-rest` directory with `go build`.

## Run the Agent

Start the agent with `./aries-agent-rest start [flags]`.

## Agent Parameters

Parameters can be set by command line arguments or environment variables:

```
Flags:
  Flags:
  -l, --agent-default-label string         Default Label for this agent. Defaults to blank if not set. Alternatively, this can be set with the following environment variable: ARIESD_DEFAULT_LABEL
  -a, --api-host string                    Host Name:Port. Alternatively, this can be set with the following environment variable: ARIESD_API_HOST
  -t, --api-token string                   Check for bearer token in the authorization header (optional). Alternatively, this can be set with the following environment variable: ARIESD_API_TOKEN
      --auto-accept string                 Auto accept requests. Possible values [true] [false]. Defaults to false if not set. Alternatively, this can be set with the following environment variable: ARIESD_AUTO_ACCEPT
      --context-provider-url strings       Remote context provider URL to get JSON-LD contexts from. This flag can be repeated, allowing setting up multiple context providers. Alternatively, this can be set with the following environment variable (in CSV format): ARIESD_CONTEXT_PROVIDER_URL
  -u, --database-prefix string             An optional prefix to be used when creating and retrieving underlying databases. Also you can use this variable for paths or connection strings as needed.  Alternatively, this can be set with the following environment variable: ARIESD_DATABASE_PREFIX
      --database-timeout string            Total time in seconds to wait until the db is available before giving up. Default: 30 seconds. Alternatively, this can be set with the following environment variable: ARIESD_DATABASE_TIMEOUT
  -q, --database-type string               The type of database to use for everything except key storage. Supported options: mem, leveldb, couchdb, mongodb, mysql, postgresql.  Alternatively, this can be set with the following environment variable: ARIESD_DATABASE_TYPE
  -h, --help                               help for start
  -r, --http-resolver-url method@url       HTTP binding DID resolver method and url. Values should be in method@url format. This flag can be repeated, allowing multiple http resolvers. Defaults to peer DID resolver if not set. Alternatively, this can be set with the following environment variable (in CSV format): ARIESD_HTTP_RESOLVER
  -i, --inbound-host scheme@url            Inbound Host Name:Port. This is used internally to start the inbound server. Values should be in scheme@url format. This flag can be repeated, allowing to configure multiple inbound transports. Alternatively, this can be set with the following environment variable: ARIESD_INBOUND_HOST
  -e, --inbound-host-external scheme@url   Inbound Host External Name:Port and values should be in scheme@url format This is the URL for the inbound server as seen externally. If not provided, then the internal inbound host will be used here. This flag can be repeated, allowing to configure multiple inbound transports. Alternatively, this can be set with the following environment variable: ARIESD_INBOUND_HOST_EXTERNAL
      --key-agreement-type string          Default key agreement type supported by this agent. Default encryption (used in DIDComm V2) key type used for key agreement creation in the agent. Alternatively, this can be set with the following environment variable: ARIESD_KEY_AGREEMENT_TYPE
      --key-type string                    Default key type supported by this agent. This flag sets the verification (and for DIDComm V1 encryption as well) key type used for key creation in the agent. Alternatively, this can be set with the following environment variable: ARIESD_KEY_TYPE
      --log-level string                   Log level. Possible values [INFO] [DEBUG] [ERROR] [WARNING] [CRITICAL] . Defaults to INFO if not set. Alternatively, this can be set with the following environment variable: ARIESD_LOG_LEVEL
      --media-type-profiles strings        Media Type Profiles supported by this agent. This flag can be repeated, allowing setting up multiple profiles. Alternatively, this can be set with the following environment variable (in CSV format): ARIESD_MEDIA_TYPE_PROFILES
  -o, --outbound-transport strings         Outbound transport type. This flag can be repeated, allowing for multiple transports. Possible values [http] [ws]. Defaults to http if not set. Alternatively, this can be set with the following environment variable: ARIESD_OUTBOUND_TRANSPORT
      --rfc0593-auto-execute string        Enables automatic execution of the issue-credential protocol withRFC0593-compliant attachment formats. Default is false. Alternatively, this can be set with the following environment variable: ARIESD_RFC0593_AUTO_EXECUTE
  -c, --tls-cert-file string               tls certificate file. Alternatively, this can be set with the following environment variable: TLS_CERT_FILE
  -k, --tls-key-file string                tls key file. Alternatively, this can be set with the following environment variable: TLS_KEY_FILE
      --transport-return-route string      Transport Return Route option. Refer https://github.com/hyperledger/aries-framework-go/blob/8449c727c7c44f47ed7c9f10f35f0cd051dcb4e9/pkg/framework/aries/framework.go#L165-L168. Alternatively, this can be set with the following environment variable: ARIESD_TRANSPORT_RETURN_ROUTE
      --web-socket-read-limit string       WebSocket read limit sets the custom max number of bytes to read for a single message when WebSocket transport is used. Defaults to 32kB. Alternatively, this can be set with the following environment variable: ARIESD_WEB_SOCKET_READ_LIMIT
  -w, --webhook-url strings                URL to send notifications to. This flag can be repeated, allowing for multiple listeners. Alternatively, this can be set with the following environment variable (in CSV format): ARIESD_WEBHOOK_URL

* Indicates a required parameter. It must be set by either command line argument or environment variable.
(If both the command line argument and environment variable are set for a parameter, then the command line argument takes precedence)
```

## Example

```shell
$ cd cmd/aries-agent-rest
$ go build
$ ./aries-agent-rest start --api-host localhost:8080 --db-path "" --inbound-host http@localhost:8081,ws@localhost:8082 --inbound-host-external http@https://example.com:8081,ws@ws://localhost:8082 --webhook-url localhost:8082 --agent-default-label MyAgent
```
