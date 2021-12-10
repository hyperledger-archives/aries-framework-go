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
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

const (
	Alice = "Alice"
	Bob   = "Bob"

	expectedPiid = "piid"
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
				require.Equal(t, msg.Type(), issuecredential.OfferCredentialMsgTypeV2)

				return expectedPiid, nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		piid, err := client.SendOffer(&OfferCredential{}, &connection.Record{
			MyDID:    Alice,
			TheirDID: Bob,
		})
		require.Equal(t, expectedPiid, piid)
		require.NoError(t, err)
	})

	t.Run("Success v3", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)

		svc := mocks.NewMockProtocolService(ctrl)
		svc.EXPECT().HandleOutbound(gomock.Any(), Alice, Bob).
			DoAndReturn(func(msg service.DIDCommMsg, _, _ string) (string, error) {
				require.Equal(t, msg.Type(), issuecredential.OfferCredentialMsgTypeV3)

				return expectedPiid, nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		piid, err := client.SendOffer(&OfferCredential{}, &connection.Record{
			MyDID:          Alice,
			TheirDID:       Bob,
			DIDCommVersion: service.V2,
		})
		require.Equal(t, expectedPiid, piid)
		require.NoError(t, err)
	})

	t.Run("Empty offer", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)

		provider.EXPECT().Service(gomock.Any()).Return(mocks.NewMockProtocolService(ctrl), nil)
		client, err := New(provider)
		require.NoError(t, err)

		piid, err := client.SendOffer(nil, &connection.Record{
			MyDID:    Alice,
			TheirDID: Bob,
		})
		require.Empty(t, piid)
		require.EqualError(t, err, errEmptyOffer.Error())
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
				require.Equal(t, msg.Type(), issuecredential.ProposeCredentialMsgTypeV2)

				return expectedPiid, nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		piid, err := client.SendProposal(&ProposeCredential{}, &connection.Record{
			MyDID:    Alice,
			TheirDID: Bob,
		})
		require.Equal(t, expectedPiid, piid)
		require.NoError(t, err)
	})

	t.Run("Success v3", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)

		svc := mocks.NewMockProtocolService(ctrl)
		svc.EXPECT().HandleOutbound(gomock.Any(), Alice, Bob).
			DoAndReturn(func(msg service.DIDCommMsg, _, _ string) (string, error) {
				require.Equal(t, msg.Type(), issuecredential.ProposeCredentialMsgTypeV3)

				return expectedPiid, nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		piid, err := client.SendProposal(&ProposeCredential{}, &connection.Record{
			MyDID:          Alice,
			TheirDID:       Bob,
			DIDCommVersion: service.V2,
		})
		require.Equal(t, expectedPiid, piid)
		require.NoError(t, err)
	})

	t.Run("Empty offer", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(mocks.NewMockProtocolService(ctrl), nil)

		client, err := New(provider)
		require.NoError(t, err)

		piid, err := client.SendProposal(nil, &connection.Record{
			MyDID:    Alice,
			TheirDID: Bob,
		})
		require.Empty(t, piid)
		require.EqualError(t, err, errEmptyProposal.Error())
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
				require.Equal(t, msg.Type(), issuecredential.RequestCredentialMsgTypeV2)

				return expectedPiid, nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		piid, err := client.SendRequest(&RequestCredential{}, &connection.Record{
			MyDID:    Alice,
			TheirDID: Bob,
		})
		require.Equal(t, expectedPiid, piid)
		require.NoError(t, err)
	})

	t.Run("Success v3", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)

		svc := mocks.NewMockProtocolService(ctrl)
		svc.EXPECT().HandleOutbound(gomock.Any(), Alice, Bob).
			DoAndReturn(func(msg service.DIDCommMsg, _, _ string) (string, error) {
				require.Equal(t, msg.Type(), issuecredential.RequestCredentialMsgTypeV3)

				return expectedPiid, nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		piid, err := client.SendRequest(&RequestCredential{}, &connection.Record{
			MyDID:          Alice,
			TheirDID:       Bob,
			DIDCommVersion: service.V2,
		})
		require.Equal(t, expectedPiid, piid)
		require.NoError(t, err)
	})

	t.Run("Empty offer", func(t *testing.T) {
		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(mocks.NewMockProtocolService(ctrl), nil)

		client, err := New(provider)
		require.NoError(t, err)

		piid, err := client.SendRequest(nil, &connection.Record{
			MyDID:    Alice,
			TheirDID: Bob,
		})
		require.Empty(t, piid)
		require.EqualError(t, err, errEmptyRequest.Error())
	})
}

func TestClient_AcceptProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionContinue("PIID", gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.AcceptProposal("PIID", &OfferCredential{}))
}

func TestClient_DeclineProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionStop("PIID", errors.New("the reason"), gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.DeclineProposal("PIID", "the reason"))
}

func TestClient_DeclineProposalRedirect(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionStop("PIID", errors.New("the reason"), gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.DeclineProposal("PIID", "the reason"), RequestRedirect("https://example.com"))
}

func TestClient_AcceptOffer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionContinue("PIID", gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.AcceptOffer("PIID", &RequestCredential{}))
}

func TestClient_DeclineOffer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionStop("PIID", errors.New("the reason")).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.DeclineOffer("PIID", "the reason"))
}

func TestClient_AcceptRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionContinue("PIID", gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.AcceptRequest("PIID", &IssueCredential{}))
}

func TestClient_DeclineRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionStop("PIID", errors.New("the reason"), gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.DeclineRequest("PIID", "the reason"))
}

func TestClient_DeclineRequestRedirect(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionStop("PIID", errors.New("the reason"), gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.DeclineRequest("PIID", "the reason", RequestRedirect("http://exmaple.com")))
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

func TestClient_NegotiateProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionContinue("PIID", gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.NegotiateProposal("PIID", &ProposeCredential{}))
}

func TestClient_AcceptCredential(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionContinue("PIID1", gomock.Any()).Return(nil)
	svc.EXPECT().ActionContinue("PIID2", gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.AcceptCredential("PIID1"))
	require.NoError(t, client.AcceptCredential("PIID2", AcceptByFriendlyNames("test"), AcceptBySkippingStorage()))
}

func TestClient_DeclineCredential(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)

	svc := mocks.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionStop("PIID", errors.New("the reason")).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.DeclineCredential("PIID", "the reason"))
}
