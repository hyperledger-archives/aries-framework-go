/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package msghandler

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/generic"
)

func ExampleRegistrar_Register() {
	registrar := NewRegistrar()

	err := registrar.Register(&generic.MockMessageSvc{})
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("new message service registered")

	// Output: new message service registered
}

func ExampleRegistrar_Unregister() {
	registrar := NewRegistrar()

	const serviceName = "sample-service"

	err := registrar.Register(&generic.MockMessageSvc{NameVal: serviceName})
	if err != nil {
		fmt.Println(err)
	}

	err = registrar.Unregister(serviceName)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("message service unregistered")

	// Output: message service unregistered
}

func ExampleRegistrar_Services() {
	registrar := NewRegistrar()

	err := registrar.Register(&generic.MockMessageSvc{NameVal: "sample-1"})
	if err != nil {
		fmt.Println(err)
	}

	err = registrar.Register(&generic.MockMessageSvc{NameVal: "sample-2"})
	if err != nil {
		fmt.Println(err)
	}

	services := registrar.Services()
	fmt.Println("available services", len(services))

	// Output: available services 2
}
