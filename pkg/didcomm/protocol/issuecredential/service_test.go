/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	issuecredentialMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/protocol/issuecredential"
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/storage"
)

func TestNew(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		storeProvider := storageMocks.NewMockProvider(ctrl)
		storeProvider.EXPECT().OpenStore(Name).Return(nil, nil)

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider)

		svc, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, svc)
	})

	t.Run("Error open store", func(t *testing.T) {
		const errMsg = "error"

		storeProvider := storageMocks.NewMockProvider(ctrl)
		storeProvider.EXPECT().OpenStore(Name).Return(nil, errors.New(errMsg))

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storeProvider)

		svc, err := New(provider)
		require.Contains(t, fmt.Sprintf("%v", err), errMsg)
		require.Nil(t, svc)
	})
}

func TestService_HandleInbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const errMsg = "error"

	store := storageMocks.NewMockStore(ctrl)

	storeProvider := storageMocks.NewMockProvider(ctrl)
	storeProvider.EXPECT().OpenStore(Name).Return(store, nil).AnyTimes()

	provider := issuecredentialMocks.NewMockProvider(ctrl)
	provider.EXPECT().Messenger().Return(nil).AnyTimes()
	provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

	t.Run("No clients", func(t *testing.T) {
		svc, err := New(provider)
		require.NoError(t, err)

		_, err = svc.HandleInbound(nil, "", "")
		require.Contains(t, fmt.Sprintf("%v", err), "no clients")
	})

	t.Run("DB error", func(t *testing.T) {
		store.EXPECT().Get(gomock.Any()).Return(nil, errors.New(errMsg))

		svc, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, svc.RegisterActionEvent(make(chan<- service.DIDCommAction)))

		msg := service.NewDIDCommMsgMap(struct{}{})
		require.NoError(t, msg.SetID(uuid.New().String()))
		_, err = svc.HandleInbound(msg, "", "")
		require.Contains(t, fmt.Sprintf("%v", err), "doHandle: getCurrentStateNameAndPIID: currentStateName: "+errMsg)
	})

	t.Run("Unrecognized msgType", func(t *testing.T) {
		svc, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, svc.RegisterActionEvent(make(chan<- service.DIDCommAction)))

		_, err = svc.HandleInbound(service.NewDIDCommMsgMap(struct{}{}), "", "")
		require.Contains(t, fmt.Sprintf("%v", err), "doHandle: nextState: unrecognized msgType: ")
	})

	t.Run("Success", func(t *testing.T) {
		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		chState := make(chan service.StateMsg, 2)
		require.NoError(t, svc.RegisterMsgEvent(chState))

		_, err = svc.HandleInbound(service.NewDIDCommMsgMap(ProposeCredential{
			Type: ProposeCredentialMsgType,
		}), "", "")
		require.NoError(t, err)
		require.Len(t, ch, 1)

		(<-ch).Stop(nil)

		var counter int
		for {
			select {
			case msg := <-chState:
				counter++
				require.Equal(t, "abandoning", msg.StateID)
				if counter == 2 {
					return
				}
			case <-time.After(time.Millisecond * 100):
				t.Error("timeout")

				return
			}
		}
	})

	t.Run("Invalid state transition", func(t *testing.T) {
		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		chState := make(chan service.StateMsg, 2)
		require.NoError(t, svc.RegisterMsgEvent(chState))

		_, err = svc.HandleInbound(service.NewDIDCommMsgMap(model.ProblemReport{
			Type: ProblemReportMsgType,
		}), "", "")
		require.Contains(t, fmt.Sprintf("%v", err), "doHandle: invalid state transition")
	})
}

func TestService_HandleOutbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const errMsg = "error"

	store := storageMocks.NewMockStore(ctrl)

	storeProvider := storageMocks.NewMockProvider(ctrl)
	storeProvider.EXPECT().OpenStore(Name).Return(store, nil).AnyTimes()

	provider := issuecredentialMocks.NewMockProvider(ctrl)
	provider.EXPECT().Messenger().Return(nil).AnyTimes()
	provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

	t.Run("DB error", func(t *testing.T) {
		store.EXPECT().Get(gomock.Any()).Return(nil, errors.New(errMsg))

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(struct{}{})
		require.NoError(t, msg.SetID(uuid.New().String()))

		_, err = svc.HandleOutbound(msg, "", "")
		require.Contains(t, fmt.Sprintf("%v", err), "doHandle: getCurrentStateNameAndPIID: currentStateName: "+errMsg)
	})

	t.Run("Unrecognized msgType", func(t *testing.T) {
		svc, err := New(provider)
		require.NoError(t, err)

		_, err = svc.HandleOutbound(service.NewDIDCommMsgMap(ProposeCredential{
			Type: ProposeCredentialMsgType,
		}), "", "")
		require.Contains(t, fmt.Sprintf("%v", err), "is not implemented yet")
	})
}

func Test_stateFromName(t *testing.T) {
	require.Equal(t, stateFromName(stateNameStart), &start{})
	require.Equal(t, stateFromName(stateNameAbandoning), &abandoning{})
	require.Equal(t, stateFromName(stateNameDone), &done{})
	require.Equal(t, stateFromName(stateNameProposalReceived), &proposalReceived{})
	require.Equal(t, stateFromName(stateNameOfferSent), &offerSent{})
	require.Equal(t, stateFromName(stateNameRequestReceived), &requestReceived{})
	require.Equal(t, stateFromName(stateNameCredentialIssued), &credentialIssued{})
	require.Equal(t, stateFromName(stateNameProposalSent), &proposalSent{})
	require.Equal(t, stateFromName(stateNameOfferReceived), &offerReceived{})
	require.Equal(t, stateFromName(stateNameRequestSent), &requestSent{})
	require.Equal(t, stateFromName(stateNameCredentialReceived), &credentialReceived{})
	require.Equal(t, stateFromName("unknown"), &noOp{})
}

func Test_nextState(t *testing.T) {
	next, err := nextState(service.NewDIDCommMsgMap(ProposeCredential{
		Type: ProposeCredentialMsgType,
	}), true)
	require.NoError(t, err)
	require.Equal(t, next, &proposalSent{})

	next, err = nextState(service.NewDIDCommMsgMap(ProposeCredential{
		Type: ProposeCredentialMsgType,
	}), false)
	require.NoError(t, err)
	require.Equal(t, next, &proposalReceived{})

	next, err = nextState(service.NewDIDCommMsgMap(OfferCredential{
		Type: OfferCredentialMsgType,
	}), true)
	require.NoError(t, err)
	require.Equal(t, next, &offerSent{})

	next, err = nextState(service.NewDIDCommMsgMap(OfferCredential{
		Type: OfferCredentialMsgType,
	}), false)
	require.NoError(t, err)
	require.Equal(t, next, &offerReceived{})

	next, err = nextState(service.NewDIDCommMsgMap(RequestCredential{
		Type: RequestCredentialMsgType,
	}), true)
	require.NoError(t, err)
	require.Equal(t, next, &requestSent{})

	next, err = nextState(service.NewDIDCommMsgMap(RequestCredential{
		Type: RequestCredentialMsgType,
	}), false)
	require.NoError(t, err)
	require.Equal(t, next, &requestReceived{})

	next, err = nextState(service.NewDIDCommMsgMap(IssueCredential{
		Type: IssueCredentialMsgType,
	}), true)
	require.NoError(t, err)
	require.Equal(t, next, &credentialIssued{})

	next, err = nextState(service.NewDIDCommMsgMap(IssueCredential{
		Type: IssueCredentialMsgType,
	}), false)
	require.NoError(t, err)
	require.Equal(t, next, &credentialReceived{})

	next, err = nextState(service.NewDIDCommMsgMap(model.Ack{
		Type: AckMsgType,
	}), false)
	require.NoError(t, err)
	require.Equal(t, next, &done{})

	next, err = nextState(service.NewDIDCommMsgMap(model.ProblemReport{
		Type: ProblemReportMsgType,
	}), false)
	require.NoError(t, err)
	require.Equal(t, next, &abandoning{})

	next, err = nextState(service.NewDIDCommMsgMap(struct{}{}), false)
	require.Error(t, err)
	require.Nil(t, next)
}

func TestService_Name(t *testing.T) {
	require.Equal(t, (*Service).Name(nil), Name)
}

func TestService_Accept(t *testing.T) {
	require.True(t, (*Service).Accept(nil, ProposeCredentialMsgType))
	require.True(t, (*Service).Accept(nil, OfferCredentialMsgType))
	require.True(t, (*Service).Accept(nil, RequestCredentialMsgType))
	require.True(t, (*Service).Accept(nil, IssueCredentialMsgType))
	require.True(t, (*Service).Accept(nil, AckMsgType))
	require.True(t, (*Service).Accept(nil, ProblemReportMsgType))
	require.False(t, (*Service).Accept(nil, "unknown"))
}

func TestService_canTriggerActionEvents(t *testing.T) {
	require.True(t, canTriggerActionEvents(service.NewDIDCommMsgMap(ProposeCredential{
		Type: ProposeCredentialMsgType,
	})))

	require.True(t, canTriggerActionEvents(service.NewDIDCommMsgMap(OfferCredential{
		Type: OfferCredentialMsgType,
	})))

	require.True(t, canTriggerActionEvents(service.NewDIDCommMsgMap(RequestCredential{
		Type: RequestCredentialMsgType,
	})))

	require.True(t, canTriggerActionEvents(service.NewDIDCommMsgMap(IssueCredential{
		Type: IssueCredentialMsgType,
	})))

	require.False(t, canTriggerActionEvents(service.NewDIDCommMsgMap(struct{}{})))
}
