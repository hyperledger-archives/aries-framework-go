/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package aries enables Go developers to build solutions based on the Hyperledger Aries project
// (https://www.hyperledger.org/projects/aries).
//
// Packages for end developer usage
//
// pkg/framework/aries: The main package of the Aries Framework. This package enables creation of context based on
// provider options. This context is used by the client packages listed below.
// Reference: https://pkg.go.dev/github.com/hyperledger/aries-framework-go/pkg/framework/aries
//
// pkg/client/didexchange: Provides did exchange protocol through SDK.
// Reference: https://pkg.go.dev/github.com/hyperledger/aries-framework-go/pkg/client/didexchange
//
// pkg/controller/restapi/operation/didexchange: Provides did exchange protocol through restapi.
// Reference: https://pkg.go.dev/github.com/hyperledger/aries-framework-go/pkg/controller/restapi/operation/didexchange
//
// Basic workflow
//
//      1) Instantiate a aries instance using a provider options.
//      2) Create a context using your aries instance.
//      3) Create a client instance using its New func, passing the context.
//      4) Use the funcs provided by each client to create your solution!
//      5) Call aries.Close() to release resources.
package aries
