# Project Structure

## Summary

The mobile bindings make use of [gomobile](https://github.com/golang/mobile) which is Golang's official mobile support tool.

As gomobile is experimental, these bindings have been developed within its constraints of which the most notable
are [type restrictions](https://godoc.org/golang.org/x/mobile/cmd/gobind#hdr-Type_restrictions).

The Golang code in this project contains wrappers for all Aries-Framework-Go controllers. 
The structs and method signatures used in these wrappers have been designed to optimise the user experience regardless
of gomobile's limitations.

The entrypoint of this project is [`main.go`](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-agent-mobile/main.go).

## Agent Controller Types

A mobile app that uses the generated SDK from this project has the option to use a local agent or a remote agent.

A local agent will handle all operations within the generated SDK.

A remote agent will forward all operations to an Aries agent deployed on an external server.

Here are examples for:

- [Android](https://github.com/trustbloc/aries-examples/blob/master/android/AriesDemo/app/src/main/java/com/github/trustbloc/ariesdemo/FirstFragment.java)
- [iOS](https://github.com/trustbloc/aries-examples/blob/master/ios/AriesDemo/AriesDemo/ViewController.m)

## Interfaces

The [`AriesController`](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-agent-mobile/pkg/api/api.go)
interface defines all operations that a wrapped Aries agent must implement.

It uses the following interfaces:

- [DIDExchangeController](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-agent-mobile/pkg/api/didexchange.go)
- [IntroduceController](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-agent-mobile/pkg/api/introduce.go)
- [IssueCredentialController](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-agent-mobile/pkg/api/issuecredential.go)
- [KMSController](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-agent-mobile/pkg/api/kms.go)
- [MediatorController](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-agent-mobile/pkg/api/mediator.go)
- [MessagingController](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-agent-mobile/pkg/api/messaging.go)
- [OutOfBandController](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-agent-mobile/pkg/api/outofband.go)
- [PresentProofController](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-agent-mobile/pkg/api/presentproof.go)
- [VDRController](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-agent-mobile/pkg/api/vdr.go)
- [VerifiableController](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-agent-mobile/pkg/api/verifiable.go)

## Implementations

### Local Agent

[`Aries`](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-agent-mobile/pkg/wrappers/command/aries.go)
implements the `AriesController` interface.
It contains an [`Aries Framework`](https://github.com/hyperledger/aries-framework-go/blob/master/pkg/framework/aries/framework.go) 
object from the Aries-Framework-Go library and a map of handlers for all controllers and their operations that are implemented in
[`controller/command`](https://github.com/hyperledger/aries-framework-go/tree/master/pkg/controller/command).

The full implementation of the local agent's wrappers can be found in
[`pkg/wrappers/command`](https://github.com/hyperledger/aries-framework-go/tree/master/cmd/aries-agent-mobile/pkg/wrappers/command).


### Remote Agent

[`Aries`](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-agent-mobile/pkg/wrappers/rest/aries.go)
implements the `AriesController` interface.
It contains a map of controller names to the endpoints of their operations. It also holds a URL to which it sends HTTP requests.

The full implementation of the remote agent's wrappers can be found in
[`pkg/wrappers/rest`](https://github.com/hyperledger/aries-framework-go/tree/master/cmd/aries-agent-mobile/pkg/wrappers/rest).

## Generating the UML diagram

A UML diagram illustrating the relationship between the interfaces and their implementations can be generated
[here](https://www.dumels.com/) using the following steps:
- Set `Repository URL` to _https://github.com/hyperledger/aries-framework-go_
- Set the project root in "Rendering options" to _cmd/aries-agent-mobile_