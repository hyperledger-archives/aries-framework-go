# Run the agent as a binary

## Build the Agent

The agent can be built from within the `cmd/aries-agent-rest` directory with `go build`.

## Run the Agent

Start the agent with `./aries-agent-rest start [flags]`.

## Agent Parameters

Parameters can be set by command line arguments or environment variables:

```
Flags:
  -l, --agent-default-label string     Default Label for this agent. Defaults to blank if not set. Alternatively, this can be set with the following environment variable: ARIESD_DEFAULT_LABEL
  -a, --api-host string                Host Name:Port. Alternatively, this can be set with the following environment variable: ARIESD_API_HOST *
  -d, --db-path string                 Path to database. Alternatively, this can be set with the following environment variable: ARIESD_DB_PATH *
  -h, --help                           help for start
  -r, --http-resolver-url string       HTTP binding DID resolver method and url. Values should be in method@url format. This flag can be repeated, allowing multiple http resolvers. Defaults to peer DID resolver if not set. Alternatively, this can be set with the following environment variable (in CSV format): ARIESD_HTTP_RESOLVER
  -i, --inbound-host string            Inbound Host Name:Port. This is used internally to start the inbound server. Alternatively, this can be set with the following environment variable: ARIESD_INBOUND_HOST *
  -e, --inbound-host-external string   Inbound Host External Name:Port. This is the URL for the inbound server as seen externally. If not provided, then the internal inbound host will be used here. Alternatively, this can be set with the following environment variable: ARIESD_INBOUND_HOST_EXTERNAL
  -w, --webhook-url strings            URL to send notifications to. This flag can be repeated, allowing for multiple listeners. Alternatively, this can be set with the following environment variable (in CSV format): ARIESD_WEBHOOK_URL *

* Indicates a required parameter. It must be set by either command line argument or environment variable.
(If both the command line argument and environment variable are set for a parameter, then the command line argument takes precedence)
```

## Example

```shell
$ cd cmd/aries-agent-rest
$ go build
$ ./aries-agent-rest start --api-host localhost:8080 --db-path "" --inbound-host localhost:8081 --inbound-host-external example.com:8081 --webhook-url localhost:8082 --agent-default-label MyAgent
```
