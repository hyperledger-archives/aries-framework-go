/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"

	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/sidetree"
)

func main() {
	doc, err := sidetree.CreateDID(os.Args[1], os.Args[2], os.Args[3], os.Args[4])
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(doc.ID)
}
