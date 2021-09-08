/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/presentproof"
)

const (
	Alice = "Alice"
	Bob   = "Bob"
)

func TestNew(t *testing.T) {
	const errMsg = "test err"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("get service error", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(nil, errors.New(errMsg))
		_, err := New(provider)
		require.EqualError(t, err, errMsg)
	})

	t.Run("cast service error", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(nil, nil)
		_, err := New(provider)
		require.EqualError(t, err, "cast service to presentproof service failed")
	})
}

func TestClient_SendRequestPresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		thid := uuid.New().String()

		svc := mocks.NewMockProtocolService(ctrl)
		svc.EXPECT().HandleInbound(gomock.Any(), service.NewDIDCommContext(Alice, Bob, nil)).
			DoAndReturn(func(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
				require.Equal(t, msg.Type(), presentproof.RequestPresentationMsgTypeV2)

				return thid, nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		result, err := client.SendRequestPresentation(&RequestPresentation{}, Alice, Bob)
		require.NoError(t, err)
		require.Equal(t, thid, result)
	})

	t.Run("Empty Invitation Presentation", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)

		provider.EXPECT().Service(gomock.Any()).Return(mocks.NewMockProtocolService(ctrl), nil)
		client, err := New(provider)
		require.NoError(t, err)

		_, err = client.SendRequestPresentation(nil, Alice, Bob)
		require.EqualError(t, err, errEmptyRequestPresentation.Error())
	})
}

func TestClient_SendRequestPresentationV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		thid := uuid.New().String()

		svc := mocks.NewMockProtocolService(ctrl)
		svc.EXPECT().HandleInbound(gomock.Any(), service.NewDIDCommContext(Alice, Bob, nil)).
			DoAndReturn(func(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
				require.Equal(t, msg.Type(), presentproof.RequestPresentationMsgTypeV3)

				return thid, nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		result, err := client.SendRequestPresentationV3(&RequestPresentationV3{}, Alice, Bob)
		require.NoError(t, err)
		require.Equal(t, thid, result)
	})

	t.Run("Empty Invitation Presentation", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)

		provider.EXPECT().Service(gomock.Any()).Return(mocks.NewMockProtocolService(ctrl), nil)
		client, err := New(provider)
		require.NoError(t, err)

		_, err = client.SendRequestPresentationV3(nil, Alice, Bob)
		require.EqualError(t, err, errEmptyRequestPresentation.Error())
	})
}

func TestClient_SendProposePresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		thid := uuid.New().String()

		svc := mocks.NewMockProtocolService(ctrl)
		svc.EXPECT().HandleInbound(gomock.Any(), service.NewDIDCommContext(Alice, Bob, nil)).
			DoAndReturn(func(msg service.DIDCommMsg, _ service.DIDCommContext) (string, error) {
				require.Equal(t, msg.Type(), presentproof.ProposePresentationMsgTypeV2)

				return thid, nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		result, err := client.SendProposePresentation(&ProposePresentation{}, Alice, Bob)
		require.NoError(t, err)
		require.Equal(t, thid, result)
	})

	t.Run("Empty Invitation Presentation", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)

		provider.EXPECT().Service(gomock.Any()).Return(mocks.NewMockProtocolService(ctrl), nil)
		client, err := New(provider)
		require.NoError(t, err)

		_, err = client.SendProposePresentation(nil, Alice, Bob)
		require.EqualError(t, err, errEmptyProposePresentation.Error())
	})
}

func TestClient_SendProposePresentationV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		thid := uuid.New().String()

		svc := mocks.NewMockProtocolService(ctrl)
		svc.EXPECT().HandleInbound(gomock.Any(), service.NewDIDCommContext(Alice, Bob, nil)).
			DoAndReturn(func(msg service.DIDCommMsg, _ service.DIDCommContext) (string, error) {
				require.Equal(t, msg.Type(), presentproof.ProposePresentationMsgTypeV3)

				return thid, nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		result, err := client.SendProposePresentationV3(&ProposePresentationV3{}, Alice, Bob)
		require.NoError(t, err)
		require.Equal(t, thid, result)
	})

	t.Run("Empty Invitation Presentation", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)

		provider.EXPECT().Service(gomock.Any()).Return(mocks.NewMockProtocolService(ctrl), nil)
		client, err := New(provider)
		require.NoError(t, err)

		_, err = client.SendProposePresentationV3(nil, Alice, Bob)
		require.EqualError(t, err, errEmptyProposePresentation.Error())
	})
}

func TestClient_AcceptRequestPresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionContinue("PIID", gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.AcceptRequestPresentation("PIID", &Presentation{}, nil))
}

func TestClient_AcceptRequestPresentationV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionContinue("PIID", gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.AcceptRequestPresentationV3("PIID", &PresentationV3{}, nil))
}

func TestClient_DeclineRequestPresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionStop("PIID", errors.New("declined")).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.DeclineRequestPresentation("PIID", "declined"))
}

func TestClient_AcceptProposePresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionContinue("PIID", gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.AcceptProposePresentation("PIID", &RequestPresentation{}))
}

func TestClient_AcceptProposePresentationV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionContinue("PIID", gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.AcceptProposePresentationV3("PIID", &RequestPresentationV3{}))
}

func TestClient_DeclineProposePresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionStop("PIID", errors.New("declined")).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.DeclineProposePresentation("PIID", "declined"))
}

func TestClient_AcceptPresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionContinue("PIID", gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.AcceptPresentation("PIID"))
}

func TestClient_DeclinePresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionStop("PIID", errors.New("declined")).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.DeclinePresentation("PIID", "declined"))
}

func TestClient_AcceptProblemReport(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionContinue("PIID", gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.AcceptProblemReport("PIID"))
}

func TestClient_NegotiateRequestPresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionContinue("PIID", gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.NegotiateRequestPresentation("PIID", &ProposePresentation{}))
}

func TestClient_NegotiateRequestPresentationV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionContinue("PIID", gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.NegotiateRequestPresentationV3("PIID", &ProposePresentationV3{}))
}
