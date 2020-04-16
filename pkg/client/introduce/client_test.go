/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	protocolOutOfBand "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	introduceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/introduce"
)

func TestNew(t *testing.T) {
	const errMsg = "test err"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("get service error", func(t *testing.T) {
		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(nil, errors.New(errMsg))
		_, err := New(provider)
		require.EqualError(t, err, errMsg)
	})

	t.Run("cast service error", func(t *testing.T) {
		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(nil, nil)
		_, err := New(provider)
		require.EqualError(t, err, "cast service to Introduce Service failed")
	})
}

func TestClient_SendProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		provider := introduceMocks.NewMockProvider(ctrl)

		svc := introduceMocks.NewMockProtocolService(ctrl)
		svc.EXPECT().
			HandleOutbound(gomock.Any(), "firstMyDID", "firstTheirDID").
			DoAndReturn(func(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
				require.Equal(t, msg.Type(), introduce.ProposalMsgType)
				require.NotEmpty(t, msg.Metadata())

				return "", nil
			})
		svc.EXPECT().
			HandleOutbound(gomock.Any(), "secondMyDID", "secondTheirDID").
			DoAndReturn(func(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
				require.Equal(t, msg.Type(), introduce.ProposalMsgType)
				require.NotEmpty(t, msg.Metadata())

				return "", nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, client.SendProposal(&introduce.Recipient{
			MyDID:    "firstMyDID",
			TheirDID: "firstTheirDID",
		}, &introduce.Recipient{
			MyDID:    "secondMyDID",
			TheirDID: "secondTheirDID",
		}))
	})

	t.Run("Error", func(t *testing.T) {
		const errMsg = "test error"

		provider := introduceMocks.NewMockProvider(ctrl)

		svc := introduceMocks.NewMockProtocolService(ctrl)
		svc.EXPECT().
			HandleOutbound(gomock.Any(), "firstMyDID", "firstTheirDID").
			Return(errors.New(errMsg))

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		require.Contains(t, fmt.Sprintf("%v", client.SendProposal(&introduce.Recipient{
			MyDID:    "firstMyDID",
			TheirDID: "firstTheirDID",
		}, &introduce.Recipient{})), errMsg)
	})
}

func TestClient_SendProposalWithOOBRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := introduceMocks.NewMockProvider(ctrl)

	svc := introduceMocks.NewMockProtocolService(ctrl)
	svc.EXPECT().
		HandleOutbound(gomock.Any(), "firstMyDID", "firstTheirDID").
		DoAndReturn(func(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
			require.Equal(t, msg.Type(), introduce.ProposalMsgType)
			require.NotEmpty(t, msg.Metadata())

			return "", nil
		})

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	req := &outofband.Request{Request: &protocolOutOfBand.Request{}}
	require.NoError(t, client.SendProposalWithOOBRequest(req, &introduce.Recipient{
		MyDID:    "firstMyDID",
		TheirDID: "firstTheirDID",
	}))
}

func TestClient_SendRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := introduceMocks.NewMockProvider(ctrl)

	svc := introduceMocks.NewMockProtocolService(ctrl)
	svc.EXPECT().
		HandleOutbound(gomock.Any(), "firstMyDID", "firstTheirDID").
		DoAndReturn(func(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
			require.Equal(t, msg.Type(), introduce.RequestMsgType)
			require.Empty(t, msg.Metadata())

			return "", nil
		})

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.SendRequest(nil, "firstMyDID", "firstTheirDID"))
}

func TestClient_AcceptProposalWithOOBRequest(t *testing.T) {
	t.Run("continues the process instance with the request", func(t *testing.T) {
		expectedPIID := "abc123"
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := introduceMocks.NewMockProvider(ctrl)
		svc := introduceMocks.NewMockProtocolService(ctrl)
		svc.EXPECT().Continue(
			gomock.AssignableToTypeOf(""),
			gomock.AssignableToTypeOf(introduce.WithOOBRequest(nil)),
		).DoAndReturn(
			func(piid string, opt introduce.Opt) error {
				require.Equal(t, expectedPIID, piid)
				require.NotNil(t, opt)
				return nil
			},
		)
		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)

		client, err := New(provider)
		require.NoError(t, err)

		err = client.AcceptProposalWithOOBRequest(expectedPIID, &outofband.Request{})
		require.NoError(t, err)
	})
}

func TestClient_AcceptRequestWithPublicOOBRequest(t *testing.T) {
	t.Run("continues the process instance with the public request", func(t *testing.T) {
		expectedPIID := "abc123"
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := introduceMocks.NewMockProvider(ctrl)
		svc := introduceMocks.NewMockProtocolService(ctrl)
		svc.EXPECT().Continue(
			gomock.AssignableToTypeOf(""),
			gomock.AssignableToTypeOf(introduce.WithPublicOOBRequest(nil, nil)),
		).DoAndReturn(
			func(piid string, opt introduce.Opt) error {
				require.Equal(t, expectedPIID, piid)
				require.NotNil(t, opt)
				return nil
			},
		)
		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)

		client, err := New(provider)
		require.NoError(t, err)

		err = client.AcceptRequestWithPublicOOBRequest(expectedPIID, &outofband.Request{}, &introduce.To{})
		require.NoError(t, err)
	})
}
