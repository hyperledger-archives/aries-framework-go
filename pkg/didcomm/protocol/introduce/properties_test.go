/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEventProps_All(t *testing.T) {
	md := &metaData{}
	md.MyDID = "MyDID"
	md.TheirDID = "TheirDID"
	md.PIID = "PIID"
	md.err = errors.New("error")

	props := newEventProps(md)

	require.Equal(t, md.MyDID, props.MyDID())
	require.Equal(t, md.TheirDID, props.TheirDID())
	require.Equal(t, md.PIID, props.PIID())
	require.Equal(t, md.err, props.Err())
	require.Equal(t, 4, len(props.All()))

	md.err = customError{errors.New("error")}
	md.MyDID = ""

	props = newEventProps(md)

	require.Equal(t, md.MyDID, props.MyDID())
	require.Equal(t, md.TheirDID, props.TheirDID())
	require.Equal(t, md.PIID, props.PIID())
	require.Equal(t, nil, props.Err())
	require.Equal(t, 2, len(props.All()))
}
