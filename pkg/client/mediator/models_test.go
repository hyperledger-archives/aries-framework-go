/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewRequest(t *testing.T) {
	result := NewRequest()
	require.NotEmpty(t, result.ID)
	require.Equal(t, "https://didcomm.org/coordinatemediation/1.0/mediate-request", result.Type)
}
