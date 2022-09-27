/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didcommutil_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/internal/didcommutil"
)

const testServiceType = "ServiceType"

func TestGetServiceType(t *testing.T) {
	t.Run("success - string", func(t *testing.T) {
		serviceType := didcommutil.GetServiceType(testServiceType)
		require.Equal(t, testServiceType, serviceType)
	})

	t.Run("success - an array of strings", func(t *testing.T) {
		serviceType := didcommutil.GetServiceType([]string{testServiceType, "OtherServiceType"})
		require.Equal(t, testServiceType, serviceType)
	})

	t.Run("success - an array of interfaces", func(t *testing.T) {
		serviceType := didcommutil.GetServiceType([]interface{}{testServiceType, "OtherServiceType"})
		require.Equal(t, testServiceType, serviceType)
	})

	t.Run("success - wrong type (return empty)", func(t *testing.T) {
		serviceType := didcommutil.GetServiceType(123)
		require.Equal(t, "", serviceType)
	})

	t.Run("success - wrong interface in an array", func(t *testing.T) {
		serviceType := didcommutil.GetServiceType([]interface{}{123, testServiceType})
		require.Equal(t, "", serviceType)
	})
}
