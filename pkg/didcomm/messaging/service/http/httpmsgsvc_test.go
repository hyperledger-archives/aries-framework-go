/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package http

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHTTPOverDIDComm(t *testing.T) {
	svc := NewHTTPOverDIDComm()
	require.NotNil(t, svc)
}

func TestHTTPOverDIDComm_Accept(t *testing.T) {
	svc := NewHTTPOverDIDComm()
	require.NotNil(t, svc)

	require.True(t, svc.Accept(OverDIDCommSpec, []string{}))
	require.False(t, svc.Accept("unknown-msg-type", []string{}))
}

func TestHTTPOverDIDComm_HandleInbound(t *testing.T) {
	svc := NewHTTPOverDIDComm()
	require.NotNil(t, svc)

	result, err := svc.HandleInbound(nil, "", "")
	require.Error(t, err)
	require.Empty(t, result)
}
func TestHTTPOverDIDComm_Name(t *testing.T) {
	svc := NewHTTPOverDIDComm()
	require.NotNil(t, svc)

	require.Equal(t, httpOverDIDComm, svc.Name())
}
