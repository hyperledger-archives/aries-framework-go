# Aries Framework Go - SDK Binding

The project can be used as a framework to build Aries agents using Go programming language. The framework is highly configurable and comes with default implementations. 

## Steps
Start writing Aries agents in few simple steps.
1. Create a [framework](https://pkg.go.dev/github.com/hyperledger/aries-framework-go/pkg/framework/aries#New)
2. Get the [Context](https://pkg.go.dev/github.com/hyperledger/aries-framework-go/pkg/framework/aries#Aries.Context) from the framework
3. Create the [client](https://pkg.go.dev/github.com/hyperledger/aries-framework-go/pkg/client) by passing the context

## Example
```
// create the framework
framework := aries.New()

// get the context
ctx := framework.Context()

// initialize the aries clients
didexchangeClient, err := didexchange.New(ctx)
```

## References
[Project GoDoc](https://pkg.go.dev/github.com/hyperledger/aries-framework-go)

[Framework Example](https://pkg.go.dev/github.com/hyperledger/aries-framework-go/pkg/framework/aries#pkg-examples)

[Aries Client Example](https://pkg.go.dev/github.com/hyperledger/aries-framework-go/pkg/client/didexchange#pkg-examples)
