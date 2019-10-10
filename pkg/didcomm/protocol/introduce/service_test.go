/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

func TestService_Action(t *testing.T) {
	svc := New()
	ch := make(chan<- service.DIDCommAction)

	// by default
	require.Nil(t, svc.GetActionEvent())

	// register action event
	require.Nil(t, svc.RegisterActionEvent(ch))
	require.Equal(t, ch, svc.GetActionEvent())

	// unregister action event
	require.Nil(t, svc.UnregisterActionEvent(ch))
	require.Nil(t, svc.GetActionEvent())
}

func TestService_Message(t *testing.T) {
	svc := New()
	ch := make(chan<- service.StateMsg)

	// by default
	require.Nil(t, svc.GetMsgEvents())

	// register message event
	require.Nil(t, svc.RegisterMsgEvent(ch))
	require.Equal(t, ch, svc.GetMsgEvents()[0])

	// unregister message event
	require.Nil(t, svc.UnregisterMsgEvent(ch))
	require.Equal(t, 0, len(svc.GetMsgEvents()))
}

func TestService_Name(t *testing.T) {
	require.Equal(t, Introduce, New().Name())
}

func TestService_Handle(t *testing.T) {
	require.Nil(t, New().Handle(&service.DIDCommMsg{}))
}

func TestService_Accept(t *testing.T) {
	require.Equal(t, false, New().Accept(""))
}
