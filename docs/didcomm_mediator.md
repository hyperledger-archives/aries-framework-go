# Aries DIDComm Router/Mediator

The aries-framework-go project can be used as a DIDComm Router/Mediator. The agents that do not 
have inbound transport can register with the router. Basically, the agent asks another agent to 
route the messages to it by asking for permission. On successful grant, agent receives the 
endpoint and routing key details. These details are used in DID Exchange Invitation or DID 
Document Service Descriptor.

## Edge Agents without Inbound Capability
The project supports DIDComm between two agents without inbound capability through a router. The 
framework needs to be initialized with Transport Return route options.

```
// create the framework with Transport return route
framework := aries.New(aries.WithTransportReturnRoute(""all"))
```

## Limitations
Currently, framework supports limited set of features. 
1. Supports only [`all`](https://github.com/hyperledger/aries-framework-go/blob/226f142f212e3a18d72220387a30bd161dd3b8c4/pkg/framework/aries/framework.go#L147) transport route option.
2. Supports only [`websocket`](https://github.com/hyperledger/aries-framework-go/blob/226f142f212e3a18d72220387a30bd161dd3b8c4/pkg/didcomm/transport/ws/outbound.go#L30) for duplex communication. ie, websocket needs to be used 
as the Outbound transport while initializing the framework for agents without inbound capabilities.

## References
- [DIDComm Router/Mediator Design - Hyperledger Wiki](https://wiki.hyperledger.org/display/ARIES/DIDComm+MediatorRouter)
- [DIDComm Router/Mediator BDD Tests](https://github.com/hyperledger/aries-framework-go/blob/master/test/bdd/features/aries_mediator_e2e_sdk.feature)
- [Aries RFC 0092: Transports Return Route](https://github.com/hyperledger/aries-rfcs/tree/master/features/0092-transport-return-route)
- [Aries RFC 0211: Route Coordination Protocol](https://github.com/hyperledger/aries-rfcs/tree/master/features/0211-route-coordination)
- [Aries RFC 0094: Forward Message](https://github.com/hyperledger/aries-rfcs/blob/master/concepts/0094-cross-domain-messaging/README.md#corerouting10forward)

