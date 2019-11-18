/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
)

func main() {
	fmt.Println("Hello from aries-framework-go")

	done := make(chan struct{})

	a, err := aries.New()
	if err != nil {
		panic(err)
	}

	ctx, err := a.Context()
	if err != nil {
		panic(err)
	}

	fmt.Println("Instantiating DID Exchange protocol client")

	c, err := didexchange.New(ctx)
	if err != nil {
		panic(err)
	}

	fmt.Println("Creating invitation")

	i, err := c.CreateInvitation("foo")
	if err != nil {
		panic(err)
	}

	fmt.Printf("ID: %s; RecipientKeys: %s\n", i.ID, i.RecipientKeys)

	<-done
}
