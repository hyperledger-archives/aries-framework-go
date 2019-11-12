# Aries Framework Go - REST Binding

The project can be used as a server agent, so that the implementors can just concentrate on writing the business logic.

## Steps
Well, running an agent in docker is as simple as [Build](agent_docker.md), [Run](agent_docker.md) and [Verify](openapi_demo.md). Also, agent can be run as a [binary](agent_cli.md). 

## Integration
The framework provides convenient Admin APIs to control the agent through [webhooks](agent_webhook.md). The agent triggers an event on registered webhooks. Refer [OpenAPI demo](openapi_demo.md) for detailed instructions.

## References
[Build and Start Reference Agent using docker](agent_docker.md)

[Run OpenAPI Demo](openapi_demo.md)

[Agent webhook support](agent_webhook.md)

[Build and Start Reference Agent as a bin](agent_cli.md)

[Generate Controller REST API Specifications](openapi_spec.md)


