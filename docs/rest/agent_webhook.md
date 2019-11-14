# Webhook Usage in Aries-agent-rest

Aries-agent-rest uses a webhook mechanism to communicate events back to the controller.

The URL that aries-agent-rest should send events to can be set with the `--webhook-url` command line argument or with the `ARIESD_WEBHOOK_URL` environment variable.

## Multiple Webhook Support

Aries-agent-rest supports multiple webhooks.
To pass in multiple webhooks, simplify repeat the `--webhook-url` argument for each url. Alternatively, a CSV list of webhook URLS can be set to the environment variable `ARIESD_WEBHOOK_URL`.

### Example

This command registers both localhost:8082 and localhost:8083 as endpoints for aries-agent-rest to send notifications to:

`./aries-agent-rest start --api-host localhost:8080 --db-path "" --inbound-host localhost:8081 --inbound-host-external example.com:8081 --webhook-url localhost:8082 --webhook-url localhost:8083 --agent-default-label MyAgent`
