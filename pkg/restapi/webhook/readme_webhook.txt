Aries-agentd uses a webhook mechanism to communicate events back to the controller.

The URL that aries-agentd should send events to can be set with the --webhook-url command line argument (or with the ARIESD_WEBHOOK_URL environment variable).

Currently, aries-agentd will notify the controller of any connection notifications.