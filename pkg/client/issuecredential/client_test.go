/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/issuecredential"
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
		require.EqualError(t, err, "cast service to issuecredential service failed")
	})
}

func TestClient_SendOffer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)

		svc := mocks.NewMockProtocolService(ctrl)
		svc.EXPECT().HandleOutbound(gomock.Any(), Alice, Bob).
			DoAndReturn(func(msg service.DIDCommMsg, _, _ string) (string, error) {
				require.Equal(t, msg.Type(), issuecredential.OfferCredentialMsgType)

				return "", nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, client.SendOffer(&issuecredential.OfferCredential{}, Alice, Bob))
	})

	t.Run("Empty offer", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)

		provider.EXPECT().Service(gomock.Any()).Return(mocks.NewMockProtocolService(ctrl), nil)
		client, err := New(provider)
		require.NoError(t, err)

		require.EqualError(t, client.SendOffer(nil, Alice, Bob), errEmptyOffer.Error())
	})
}

func TestClient_SendProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)

		svc := mocks.NewMockProtocolService(ctrl)
		svc.EXPECT().HandleOutbound(gomock.Any(), Alice, Bob).
			DoAndReturn(func(msg service.DIDCommMsg, _, _ string) (string, error) {
				require.Equal(t, msg.Type(), issuecredential.ProposeCredentialMsgType)

				return "", nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, client.SendProposal(&issuecredential.ProposeCredential{}, Alice, Bob))
	})

	t.Run("Empty offer", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(mocks.NewMockProtocolService(ctrl), nil)

		client, err := New(provider)
		require.NoError(t, err)

		require.EqualError(t, client.SendProposal(nil, Alice, Bob), errEmptyProposal.Error())
	})
}

func TestClient_SendRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)

		svc := mocks.NewMockProtocolService(ctrl)
		svc.EXPECT().HandleOutbound(gomock.Any(), Alice, Bob).
			DoAndReturn(func(msg service.DIDCommMsg, _, _ string) (string, error) {
				require.Equal(t, msg.Type(), issuecredential.RequestCredentialMsgType)

				return "", nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, client.SendRequest(&issuecredential.RequestCredential{}, Alice, Bob))
	})

	t.Run("Empty offer", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(mocks.NewMockProtocolService(ctrl), nil)

		client, err := New(provider)
		require.NoError(t, err)

		require.EqualError(t, client.SendRequest(nil, Alice, Bob), errEmptyRequest.Error())
	})
}
