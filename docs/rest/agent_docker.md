# Run the agent as docker container

## Build the Agent
Build the docker image for `aries-agentd` by running following make target from project root directory. 

`make agent-docker`

## Run the Agent
Above target will build docker image `aries-framework-go/agent` which can be used to start agent by running command as simple as 

```
 docker run aries-framework-go/agent start [flags] 
```

Details about flags can be found [here](agent_cli.md#Agent-Parameters)
