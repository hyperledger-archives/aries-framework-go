/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
)

func TestStateFromName(t *testing.T) {
	t.Run("valid state names", func(t *testing.T) {
		states := []state{
			&stateInitial{},
			&statePrepareResponse{},
			&stateAwaitResponse{},
			&stateDone{},
		}

		for _, expected := range states {
			actual, err := stateFromName(expected.Name())
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		}
	})

	t.Run("invalid state name", func(t *testing.T) {
		_, err := stateFromName("invalid")
		require.Error(t, err)
	})
}

func TestStateInitial_Execute(t *testing.T) {
	t.Run("handles inbound invitation", func(t *testing.T) {
		s := &stateInitial{}
		next, finish, halt, err := s.Execute(&context{Inbound: true}, nil)
		require.NoError(t, err)
		require.IsType(t, &statePrepareResponse{}, next)
		require.NotNil(t, finish)
		require.False(t, halt)
	})
}

func TestStateAwaitResponse_Execute(t *testing.T) {
	t.Run("error if not an inbound message", func(t *testing.T) {
		s := &stateAwaitResponse{}

		_, _, _, err := s.Execute(&context{}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot execute")
	})
}

func TestStatePrepareResponse_Execute(t *testing.T) {
	t.Run("new connection", func(t *testing.T) {
		t.Run("error while saving attachment handling state", func(t *testing.T) {
			expected := errors.New("test")
			ctx := &context{Invitation: &Invitation{
				Requests: []*decorator.AttachmentV2{{
					ID: uuid.New().String(),
					Data: decorator.AttachmentData{
						JSON: map[string]interface{}{},
					},
				}},
			}}
			deps := &dependencies{
				saveAttchStateFunc: func(*attachmentHandlingState) error {
					return expected
				},
			}
			s := &statePrepareResponse{}

			_, _, _, err := s.Execute(ctx, deps)
			require.ErrorIs(t, err, expected)
		})
	})
}
