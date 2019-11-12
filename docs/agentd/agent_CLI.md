# Building the Agent

The agent can be built from within the `cmd/aries-agentd` directory with `go build`.

# Running the Agent

Start the agent with `./aries-agentd start [flags]`.

# Agent Parameters

Parameters can be set by command line arguments or environment variables:

```
Flags:
  -l, --agent-default-label string     Default Label for this agent. Defaults to blank if not set. Alternatively, this can be set with the following environment variable: ARIESD_DEFAULT_LABEL
  -a, --api-host string                Host Name:Port. Alternatively, this can be set with the following environment variable: ARIESD_API_HOST *
  -d, --db-path string                 Path to database. Alternatively, this can be set with the following environment variable: ARIESD_DB_PATH *
  -h, --help                           help for start
  -i, --inbound-host string            Inbound Host Name:Port. This is used internally to start the inbound server. Alternatively, this can be set with the following environment variable: ARIESD_INBOUND_HOST *
  -e, --inbound-host-external string   Inbound Host External Name:Port. This is the URL for the inbound server as seen externally. If not provided, then the internal inbound host will be used here. Alternatively, this can be set with the following environment variable: ARIESD_INBOUND_HOST_EXTERNAL
  -w, --webhook-url strings            URL to send notifications to. This flag can be repeated, allowing for multiple listeners. Alternatively, this can be set with the following environment variable (in CSV format): ARIESD_WEBHOOK_URL *

* Indicates a required parameter. It must be set by either command line argument or environment variable.
(If both the command line argument and environment variable are set for a parameter, then the command line argument takes precedence)
```

## Example

```shell
$ cd cmd/aries-agentd
$ go build -o $HOME/go/bin
$ $HOME/go/bin/aries-agentd start --api-host localhost:8080 --db-path "" --inbound-host localhost:8081 --inbound-host-external example.com:8081 --webhook-url localhost:8082 --agent-default-label MyAgent
```
