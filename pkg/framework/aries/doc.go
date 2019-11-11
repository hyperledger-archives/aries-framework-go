/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

/*
Package aries provides a pluggable dependency framework, where implementors can customize primitives via
Service Provider Interfaces (SPIs). The framework comes with a "batteries included" model where default
primitives are included. The framework holds a context that can be used to create aries clients.

Usage:
	// create the framework
	framework := aries.New()

	// get the context
	ctx := framework.Context()

	// initialize the aries clients
	didexchangeClient, err := didexchange.New(ctx)
*/
package aries
