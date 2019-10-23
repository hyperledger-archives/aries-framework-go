/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAction_MsgEvents(t *testing.T) {
	m := Message{}
	require.Nil(t, m.MsgEvents())
}

func TestAction_RegisterMsgEvent(t *testing.T) {
	m := Message{}

	// cannot register nil channel
	require.EqualError(t, m.RegisterMsgEvent(nil), ErrNilChannel.Error())

	ch := make(chan<- StateMsg)
	require.Nil(t, m.RegisterMsgEvent(ch))
	require.Equal(t, 1, len(m.MsgEvents()))

	// double register
	require.Nil(t, m.RegisterMsgEvent(ch))
	require.Equal(t, 2, len(m.MsgEvents()))
}

func TestAction_UnregisterMsgEvent(t *testing.T) {
	m := Message{}

	ch := make(chan<- StateMsg)
	require.Nil(t, m.RegisterMsgEvent(ch))
	require.Equal(t, 1, len(m.MsgEvents()))
	require.Nil(t, m.UnregisterMsgEvent(ch))
	require.Equal(t, 0, len(m.MsgEvents()))

	// double register
	require.Nil(t, m.RegisterMsgEvent(ch))
	require.Nil(t, m.RegisterMsgEvent(ch))
	require.Equal(t, 2, len(m.MsgEvents()))
	require.Nil(t, m.UnregisterMsgEvent(ch))
	require.Equal(t, 0, len(m.MsgEvents()))

	// no error if nothing to unregister
	require.Nil(t, m.UnregisterMsgEvent(ch))
}
