/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockservice "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/service"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
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

	t.Run("handshake-reuse", func(t *testing.T) {
		t.Run("error if cannot fetch connection ID", func(t *testing.T) {
			expected := errors.New("test")
			ctx := &context{
				Inbound: true,
				Action:  Action{Msg: service.NewDIDCommMsgMap(&HandshakeReuse{Type: HandshakeReuseMsgType})},
			}
			deps := &dependencies{
				connections: &mockConnRecorder{
					getConnIDByDIDsErr: expected,
				},
			}
			s := &stateAwaitResponse{}

			_, _, _, err := s.Execute(ctx, deps)
			require.ErrorIs(t, err, expected)
		})

		t.Run("error if cannot fetch connection record", func(t *testing.T) {
			expected := errors.New("test")
			ctx := &context{
				Inbound: true,
				Action:  Action{Msg: service.NewDIDCommMsgMap(&HandshakeReuse{Type: HandshakeReuseMsgType})},
			}
			deps := &dependencies{
				connections: &mockConnRecorder{
					getConnRecordErr: expected,
				},
			}
			s := &stateAwaitResponse{}

			_, _, _, err := s.Execute(ctx, deps)
			require.ErrorIs(t, err, expected)
		})

		t.Run("error if connection is not in state 'completed'", func(t *testing.T) {
			ctx := &context{
				Inbound: true,
				Action:  Action{Msg: service.NewDIDCommMsgMap(&HandshakeReuse{Type: HandshakeReuseMsgType})},
			}
			deps := &dependencies{
				connections: &mockConnRecorder{
					getConnRecordVal: &connection.Record{State: "initial"},
				},
			}
			s := &stateAwaitResponse{}

			_, _, _, err := s.Execute(ctx, deps)
			require.Error(t, err)
			require.Contains(t, err.Error(), "unexpected state for connection")
		})
	})
}

func TestStatePrepareResponse_Execute(t *testing.T) {
	t.Run("new connection", func(t *testing.T) {
		t.Run("error while saving attachment handling state", func(t *testing.T) {
			expected := errors.New("test")
			ctx := &context{Invitation: &Invitation{
				Requests: []*decorator.Attachment{{
					ID: uuid.New().String(),
					Data: decorator.AttachmentData{
						JSON: map[string]interface{}{},
					},
				}},
			}}
			deps := &dependencies{
				connections: nil,
				didSvc:      &mockdidexchange.MockDIDExchangeSvc{},
				saveAttchStateFunc: func(*attachmentHandlingState) error {
					return expected
				},
			}
			s := &statePrepareResponse{}

			_, _, _, err := s.Execute(ctx, deps)
			require.ErrorIs(t, err, expected)
		})
	})

	t.Run("connection reuse", func(t *testing.T) {
		t.Run("advances to next state and sends handshake-reuse", func(t *testing.T) {
			savedAttachmentState := false
			ctx := &context{
				Invitation: &Invitation{
					Services: []interface{}{theirDID},
					Requests: []*decorator.Attachment{{
						ID: uuid.New().String(),
						Data: decorator.AttachmentData{
							JSON: map[string]interface{}{},
						},
					}},
				},
				ReuseConnection: theirDID,
			}
			deps := &dependencies{
				connections: &mockConnRecorder{queryConnRecordsVal: []*connection.Record{{
					TheirDID: theirDID,
					State:    didexchange.StateIDCompleted,
				}}},
				saveAttchStateFunc: func(*attachmentHandlingState) error {
					savedAttachmentState = true

					return nil
				},
			}
			s := &statePrepareResponse{}

			next, finish, halt, err := s.Execute(ctx, deps)
			require.NoError(t, err)
			require.IsType(t, &stateAwaitResponse{}, next)
			require.True(t, halt)

			sent := false

			messenger := &mockservice.MockMessenger{
				ReplyToMsgFunc: func(_ service.DIDCommMsgMap, out service.DIDCommMsgMap, _ string, _ string) error {
					require.Equal(t, HandshakeReuseMsgType, out.Type())
					sent = true

					return nil
				},
			}

			err = finish(messenger)
			require.NoError(t, err)
			require.True(t, savedAttachmentState)
			require.True(t, sent)
		})

		t.Run("error if cannot query connection records", func(t *testing.T) {
			expected := errors.New("test")
			ctx := &context{
				Inbound:            true,
				ReuseAnyConnection: true,
			}
			deps := &dependencies{
				connections: &mockConnRecorder{queryConnRecordsErr: expected},
			}
			s := &statePrepareResponse{}

			_, _, _, err := s.Execute(ctx, deps)
			require.ErrorIs(t, err, expected)
		})

		t.Run("error if cannot find matching connection record", func(t *testing.T) {
			ctx := &context{
				Inbound:            true,
				ReuseAnyConnection: true,
				Invitation: &Invitation{
					Services: []interface{}{theirDID},
				},
			}
			deps := &dependencies{
				connections: &mockConnRecorder{},
			}
			s := &statePrepareResponse{}

			_, _, _, err := s.Execute(ctx, deps)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no existing connection record found for the invitation")
		})

		t.Run("error when saving attachment handling state", func(t *testing.T) {
			expected := errors.New("test")
			ctx := &context{
				Inbound:         true,
				ReuseConnection: theirDID,
				Invitation: &Invitation{
					Services: []interface{}{theirDID},
					Requests: []*decorator.Attachment{{
						ID: uuid.New().String(),
						Data: decorator.AttachmentData{
							JSON: map[string]interface{}{},
						},
					}},
				},
			}
			deps := &dependencies{
				connections: &mockConnRecorder{queryConnRecordsVal: []*connection.Record{{
					TheirDID: theirDID,
					State:    didexchange.StateIDCompleted,
				}}},
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

type mockConnRecorder struct {
	saveInvErr          error
	getConnRecordVal    *connection.Record
	getConnRecordErr    error
	getConnIDByDIDsVal  string
	getConnIDByDIDsErr  error
	queryConnRecordsVal []*connection.Record
	queryConnRecordsErr error
}

func (m *mockConnRecorder) SaveInvitation(string, interface{}) error {
	return m.saveInvErr
}

func (m *mockConnRecorder) GetConnectionRecord(string) (*connection.Record, error) {
	return m.getConnRecordVal, m.getConnRecordErr
}

func (m *mockConnRecorder) GetConnectionIDByDIDs(string, string) (string, error) {
	return m.getConnIDByDIDsVal, m.getConnIDByDIDsErr
}

func (m *mockConnRecorder) QueryConnectionRecords() ([]*connection.Record, error) {
	return m.queryConnRecordsVal, m.queryConnRecordsErr
}
