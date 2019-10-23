/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAction_ActionEvent(t *testing.T) {
	a := Action{}
	require.Nil(t, a.ActionEvent())
}

func TestAction_RegisterActionEvent(t *testing.T) {
	a := Action{}
	// nil error
	require.EqualError(t, a.RegisterActionEvent(nil), ErrNilChannel.Error())

	// channel should be the same
	ch := make(chan DIDCommAction)
	require.Nil(t, a.RegisterActionEvent(ch))
	require.EqualValues(t, ch, a.ActionEvent())

	// register the same channel twice
	newCh := make(chan DIDCommAction)
	require.EqualError(t, a.RegisterActionEvent(newCh), ErrChannelRegistered.Error())
}

func TestAction_UnregisterActionEvent(t *testing.T) {
	a := Action{}

	// nil channel
	require.EqualError(t, a.UnregisterActionEvent(nil), ErrNilChannel.Error())

	// channel was not registered
	ch := make(chan DIDCommAction)
	require.EqualError(t, a.UnregisterActionEvent(ch), ErrInvalidChannel.Error())

	// happy path
	require.Nil(t, a.RegisterActionEvent(ch))
	require.Nil(t, a.UnregisterActionEvent(ch))
}
