/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacyconnection

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConnectionEvent(t *testing.T) {
	ev := connectionEvent{connectionID: "abc", invitationID: "xyz"}
	require.Equal(t, ev.ConnectionID(), "abc")
	require.Equal(t, ev.InvitationID(), "xyz")
	require.Equal(t, ev.All()["connectionID"], ev.ConnectionID())
	require.Equal(t, ev.All()["invitationID"], ev.InvitationID())

	err := errors.New("processing error")
	evErr := connectionEventError{err: err}
	require.Equal(t, err.Error(), evErr.Error())
	require.Equal(t, evErr.All()["error"], evErr.Error())

	evErr = connectionEventError{}
	require.Equal(t, "", evErr.Error())
}
