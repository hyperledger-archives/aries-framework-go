/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didcreator

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	serviceEndpoint = "service-endpoint"
	serviceType     = "service-type"
	keyType         = "key-type"
)

func TestDIDCreator(t *testing.T) {
	t.Run("test all creator options", func(t *testing.T) {
		opts := testOptions(WithKeyType(keyType),
			WithServiceEndpoint(serviceEndpoint),
			WithServiceType(serviceType))
		require.NotNil(t, opts)
		require.Equal(t, serviceType, opts.ServiceType)
		require.Equal(t, serviceEndpoint, opts.ServiceEndpoint)
		require.Equal(t, keyType, opts.KeyType)
	})
}

func testOptions(opts ...DocOpts) *CreateDIDOpts {
	creator := &CreateDIDOpts{}

	for _, option := range opts {
		option(creator)
	}

	return creator
}
