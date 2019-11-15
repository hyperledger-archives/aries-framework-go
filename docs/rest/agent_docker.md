# Run the agent as docker container

## Build the Agent
Build the docker image for `aries-agent-rest` by running following make target from project root directory. 

`make agent-rest-docker`

## Run the Agent
Above target will build docker image `aries-framework-go/agent-rest` which can be used to start agent by running command as simple as 

```
 docker run aries-framework-go/agent-rest start [flags] 
```

Details about flags can be found [here](agent_cli.md#Agent-Parameters)
