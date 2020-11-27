# Aries DIDComm Router/Mediator

The aries-framework-go project can be used as a DIDComm Router/Mediator. The agents that do not 
have inbound transport can register with the router. Basically, the agent asks another agent to 
route the messages to it by asking for permission. On successful grant, agent receives the 
endpoint and routing key details. These details are used in DID Exchange Invitation or DID 
Document Service Descriptor.

## Mediator Setup
To set up the project as a mediator, configure `WebSocket` for inbound and outbound communication.

### sdk
```
// add http inbound and outbound
opts = append(opts, http_inbound, http_outbound))

// add websocket inbound and outbound
inbound, err := ws.NewInbound(...)
if err != nil {
	return err
}

opts = append(opts, aries.WithInboundTransport(inbound), aries.WithOutboundTransports(ws.NewOutbound()))
framework := aries.New(aries.WithInboundTransport(inbound), aries.WithOutboundTransports(ws.NewOutbound()))
```

### rest/docker
```
- ARIESD_INBOUND_HOST=http@$<http_internal>,ws@$<ws_internal>
- ARIESD_INBOUND_HOST_EXTERNAL=http@$<http_extenal_url>,ws@$<ws_extenal_url>
- ARIESD_OUTBOUND_TRANSPORT=http,ws
```

## Edge Agents without Inbound Capability
The project supports DIDComm between two agents without inbound capability through a router. The 
framework needs to be initialized with Transport Return route options.

### sdk
```
// create the framework with Transport return route and websocket outbound
framework := aries.New(aries.WithTransportReturnRoute("all"), aries.WithOutboundTransports(ws.NewOutbound())
```

### rest/docker
```
- ARIESD_TRANSPORT_RETURN_ROUTE=all
- ARIESD_OUTBOUND_TRANSPORT=ws
```

## Limitations
Currently, framework supports limited set of features. 
1. Supports only [`all`](https://github.com/hyperledger/aries-rfcs/tree/master/features/0092-transport-return-route#reference) transport route option.
2. Supports only [`websocket`](https://github.com/hyperledger/aries-framework-go/blob/226f142f212e3a18d72220387a30bd161dd3b8c4/pkg/didcomm/transport/ws/outbound.go#L30) for duplex communication. ie, websocket needs to be used 
as the Outbound transport while initializing the framework for agents without inbound capabilities.
3. [Aries RFC 0211: Mediator Coordination Protocol](https://github.com/hyperledger/aries-rfcs/tree/master/features/0211-route-coordination) : No support for Key List Query and Key List messages - [Issue #942](https://github.com/hyperledger/aries-framework-go/issues/942). 
4. [Aries RFC 0094: Forward Message](https://github.com/hyperledger/aries-rfcs/blob/master/concepts/0094-cross-domain-messaging/README.md#corerouting10forward) : Uses recipient key in the `to` field instead of DID keyid - [Issue #965](https://github.com/hyperledger/aries-framework-go/issues/965). 
5. [Aries RFC 0212: Pickup Protocol](https://github.com/hyperledger/aries-rfcs/tree/master/features/0212-pickup) : No support for Message Query With Message Id List message - [Issue #2351](https://github.com/hyperledger/aries-framework-go/issues/2351).

## References
- [DIDComm Router/Mediator Design - Hyperledger Wiki](https://wiki.hyperledger.org/display/ARIES/DIDComm+MediatorRouter)
- [DIDComm Router/Mediator BDD Tests](https://github.com/hyperledger/aries-framework-go/blob/master/test/bdd/features/aries_mediator_e2e_sdk.feature)
- [Aries RFC 0092: Transports Return Route](https://github.com/hyperledger/aries-rfcs/tree/master/features/0092-transport-return-route)
- [Aries RFC 0211: Mediator Coordination Protocol](https://github.com/hyperledger/aries-rfcs/tree/master/features/0211-route-coordination)
- [Aries RFC 0094: Forward Message](https://github.com/hyperledger/aries-rfcs/blob/master/concepts/0094-cross-domain-messaging/README.md#corerouting10forward)
- [Aries RFC 0212: Pickup Protocol](https://github.com/hyperledger/aries-rfcs/tree/master/features/0212-pickup)
