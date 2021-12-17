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
	mocksintroduce "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/introduce"
)

const expectedPIID = "piid"

func TestNew(t *testing.T) {
	const errMsg = "test err"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("get service error", func(t *testing.T) {
		provider := mocksintroduce.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(nil, errors.New(errMsg))
		_, err := New(provider)
		require.EqualError(t, err, errMsg)
	})

	t.Run("cast service error", func(t *testing.T) {
		provider := mocksintroduce.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(nil, nil)
		_, err := New(provider)
		require.EqualError(t, err, "cast service to Introduce Service failed")
	})
}

func TestClient_Actions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		provider := mocksintroduce.NewMockProvider(ctrl)

		svc := mocksintroduce.NewMockProtocolService(ctrl)
		expected := []introduce.Action{{PIID: "1"}, {PIID: "2"}}
		svc.EXPECT().Actions().Return(expected, nil)

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		actions, err := client.Actions()
		require.NoError(t, err)
		// client Actions is an array of new type of Action, the test can't check for value equality since client Action
		// is, even though it's anp service Action, is considered a different type therefore fails quality checks. Simply
		// check for set values instead.
		require.Equal(t, len(expected), len(actions))
		require.Equal(t, expected[0].PIID, actions[0].PIID)
		require.Equal(t, expected[1].PIID, actions[1].PIID)
	})
}

func TestClient_SendProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		provider := mocksintroduce.NewMockProvider(ctrl)

		svc := mocksintroduce.NewMockProtocolService(ctrl)
		svc.EXPECT().
			HandleOutbound(gomock.Any(), "firstMyDID", "firstTheirDID").
			DoAndReturn(func(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
				require.Equal(t, msg.Type(), introduce.ProposalMsgType)
				require.NotEmpty(t, msg.Metadata())

				return expectedPIID, nil
			})
		svc.EXPECT().
			HandleOutbound(gomock.Any(), "secondMyDID", "secondTheirDID").
			DoAndReturn(func(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
				require.Equal(t, msg.Type(), introduce.ProposalMsgType)
				require.NotEmpty(t, msg.Metadata())

				return expectedPIID, nil
			})

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		piid, err := client.SendProposal(&Recipient{
			MyDID:    "firstMyDID",
			TheirDID: "firstTheirDID",
		}, &Recipient{
			MyDID:    "secondMyDID",
			TheirDID: "secondTheirDID",
		})
		require.Equal(t, expectedPIID, piid)
		require.NoError(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		const errMsg = "test error"

		provider := mocksintroduce.NewMockProvider(ctrl)

		svc := mocksintroduce.NewMockProtocolService(ctrl)
		svc.EXPECT().
			HandleOutbound(gomock.Any(), "firstMyDID", "firstTheirDID").
			Return("", errors.New(errMsg))

		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
		client, err := New(provider)
		require.NoError(t, err)

		piid, err := client.SendProposal(&Recipient{
			MyDID:    "firstMyDID",
			TheirDID: "firstTheirDID",
		}, &Recipient{})
		require.Empty(t, piid)
		require.Contains(t, fmt.Sprintf("%v", err), errMsg)
	})
}

func TestClient_SendProposalWithOOBInvitation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocksintroduce.NewMockProvider(ctrl)

	svc := mocksintroduce.NewMockProtocolService(ctrl)
	svc.EXPECT().
		HandleOutbound(gomock.Any(), "firstMyDID", "firstTheirDID").
		DoAndReturn(func(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
			require.Equal(t, msg.Type(), introduce.ProposalMsgType)
			require.NotEmpty(t, msg.Metadata())

			return expectedPIID, nil
		})

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	req := &outofband.Invitation{}
	piid, err := client.SendProposalWithOOBInvitation(req, &Recipient{
		MyDID:    "firstMyDID",
		TheirDID: "firstTheirDID",
	})
	require.Equal(t, expectedPIID, piid)
	require.NoError(t, err)
}

func TestClient_SendRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocksintroduce.NewMockProvider(ctrl)

	svc := mocksintroduce.NewMockProtocolService(ctrl)
	svc.EXPECT().
		HandleOutbound(gomock.Any(), "firstMyDID", "firstTheirDID").
		DoAndReturn(func(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
			require.Equal(t, msg.Type(), introduce.RequestMsgType)
			require.Empty(t, msg.Metadata())

			return expectedPIID, nil
		})

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	piid, err := client.SendRequest(&PleaseIntroduceTo{}, "firstMyDID", "firstTheirDID")
	require.Equal(t, expectedPIID, piid)
	require.NoError(t, err)
}

func TestClient_AcceptProposalWithOOBRequest(t *testing.T) {
	t.Run("continues the process instance with the request", func(t *testing.T) {
		expectedPIID := "abc123"
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := mocksintroduce.NewMockProvider(ctrl)
		svc := mocksintroduce.NewMockProtocolService(ctrl)
		svc.EXPECT().ActionContinue(
			gomock.AssignableToTypeOf(""),
			gomock.AssignableToTypeOf(introduce.WithOOBInvitation(nil)),
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

		err = client.AcceptProposalWithOOBInvitation(expectedPIID, &outofband.Invitation{})
		require.NoError(t, err)
	})
}

func TestClient_AcceptProposal(t *testing.T) {
	t.Run("continues the process instance", func(t *testing.T) {
		const expectedPIID = "abc123"

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		svc := mocksintroduce.NewMockProtocolService(ctrl)
		svc.EXPECT().ActionContinue(gomock.Eq(expectedPIID), gomock.Nil()).Return(nil)

		provider := mocksintroduce.NewMockProvider(ctrl)
		provider.EXPECT().Service(gomock.Any()).Return(svc, nil)

		client, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, client.AcceptProposal(expectedPIID))
	})
}

func TestClient_AcceptRequestWithPublicOOBRequest(t *testing.T) {
	t.Run("continues the process instance with the public request", func(t *testing.T) {
		expectedPIID := "abc123"
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := mocksintroduce.NewMockProvider(ctrl)
		svc := mocksintroduce.NewMockProtocolService(ctrl)
		svc.EXPECT().ActionContinue(
			gomock.AssignableToTypeOf(""),
			gomock.AssignableToTypeOf(introduce.WithPublicOOBInvitation(nil, nil)),
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

		err = client.AcceptRequestWithPublicOOBInvitation(expectedPIID, &outofband.Invitation{}, &To{})
		require.NoError(t, err)
	})
}

func TestClient_DeclineProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocksintroduce.NewMockProvider(ctrl)

	svc := mocksintroduce.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionStop("PIID", errors.New("the reason")).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.DeclineProposal("PIID", "the reason"))
}

func TestClient_DeclineRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocksintroduce.NewMockProvider(ctrl)

	svc := mocksintroduce.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionStop("PIID", errors.New("the reason")).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.DeclineRequest("PIID", "the reason"))
}

func TestClient_AcceptProblemReport(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocksintroduce.NewMockProvider(ctrl)

	svc := mocksintroduce.NewMockProtocolService(ctrl)
	svc.EXPECT().ActionContinue("PIID", gomock.Any()).Return(nil)

	provider.EXPECT().Service(gomock.Any()).Return(svc, nil)
	client, err := New(provider)
	require.NoError(t, err)

	require.NoError(t, client.AcceptProblemReport("PIID"))
}
