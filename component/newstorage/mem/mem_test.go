/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mem

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/test/newstorage"
)

func TestCommon(t *testing.T) {
	provider := NewProvider()

	newstorage.TestAll(t, provider)
}
