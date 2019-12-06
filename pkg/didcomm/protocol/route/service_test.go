/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServiceNew(t *testing.T) {
	t.Run("test new service - success", func(t *testing.T) {
		svc, err := New(&mockProvider{})
		require.NoError(t, err)
		require.Equal(t, Coordination, svc.Name())
	})

	t.Run("test new service name - failure", func(t *testing.T) {
		_, err := New(&mockProvider{openStoreErr: errors.New("error opening the store")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "open route coordination store")
	})
}

func TestServiceAccept(t *testing.T) {
	s := &Service{}

	require.Equal(t, true, s.Accept(RequestMsgType))
	require.Equal(t, true, s.Accept(GrantMsgType))
	require.Equal(t, true, s.Accept(KeyListUpdateMsgType))
	require.Equal(t, true, s.Accept(KeyListUpdateResponseMsgType))
	require.Equal(t, false, s.Accept("unsupported msg type"))
}

func TestServiceHandleInbound(t *testing.T) {
	t.Run("test handle outbound ", func(t *testing.T) {
		svc, err := New(&mockProvider{})
		require.NoError(t, err)

		_, err = svc.HandleInbound(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not implemented")
	})
}

func TestServiceHandleOutbound(t *testing.T) {
	t.Run("test handle outbound ", func(t *testing.T) {
		svc, err := New(&mockProvider{})
		require.NoError(t, err)

		err = svc.HandleOutbound(nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not implemented")
	})
}
