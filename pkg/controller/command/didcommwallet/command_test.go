/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didcommwallet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	outofbandClient "github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	issuecredentialsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	outofbandSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	oobv2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	presentproofSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	mockoutofbandv2 "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockissuecredential "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/issuecredential"
	mockmediator "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockoutofband "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/outofband"
	mockpresentproof "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/presentproof"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

const (
	sampleUserID         = "sample-user01"
	samplePassPhrase     = "fakepassphrase"
	sampleCommandError   = "sample-command-error-01"
	sampleFakeTkn        = "sample-fake-token-01"
	webRedirectStatusKey = "status"
	webRedirectURLKey    = "url"
	exampleWebRedirect   = "http://example.com/sample"
)

func TestNew(t *testing.T) {
	t.Run("successfully create new command instance", func(t *testing.T) {
		cmd := New(newMockProvider(t), &Config{})
		require.NotNil(t, cmd)

		require.Len(t, cmd.GetHandlers(), 23)
	})
}

func TestCommand_Connect(t *testing.T) {
	const sampleDIDCommUser = "sample-didcomm-user01"

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	t.Run("successfully perform DID connect", func(t *testing.T) {
		sampleConnID := uuid.New().String()

		oobSvc := &mockoutofband.MockOobService{
			AcceptInvitationHandle: func(*outofbandSvc.Invitation, outofbandSvc.Options) (string, error) {
				return sampleConnID, nil
			},
		}
		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc

		didexSvc := &mockdidexchange.MockDIDExchangeSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:       service.PostState,
					StateID:    didexchange.StateIDCompleted,
					Properties: &mockdidexchange.MockEventProperties{ConnID: sampleConnID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[didexchange.DIDExchange] = didexSvc

		cmdDidComm := New(mockctx, &Config{})

		request := &ConnectRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			Invitation: &outofbandClient.Invitation{},
			ConnectOpts: ConnectOpts{
				MyLabel: "sample-label",
			},
		}

		var b bytes.Buffer
		cmdErr := cmdDidComm.Connect(&b, getReader(t, &request))
		require.NoError(t, cmdErr)

		var response ConnectResponse
		require.NoError(t, json.NewDecoder(&b).Decode(&response))
		require.NotEmpty(t, response)
		require.Equal(t, sampleConnID, response.ConnectionID)
	})

	t.Run("did connect failure", func(t *testing.T) {
		oobSvc := &mockoutofband.MockOobService{
			AcceptInvitationHandle: func(*outofbandSvc.Invitation, outofbandSvc.Options) (string, error) {
				return "", fmt.Errorf(sampleCommandError)
			},
		}
		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc

		cmd := New(mockctx, &Config{})

		request := &ConnectRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			Invitation: &outofbandClient.Invitation{},
			ConnectOpts: ConnectOpts{
				MyLabel: "sample-label",
			},
		}

		var b bytes.Buffer
		cmdErr := cmd.Connect(&b, getReader(t, &request))
		require.Error(t, cmdErr)

		validateError(t, cmdErr, command.ExecuteError, DIDConnectErrorCode, sampleCommandError)
		validateError(t, cmdErr, command.ExecuteError, DIDConnectErrorCode, "failed to accept invitation")
		require.Empty(t, b.Bytes())
	})

	t.Run("did connect failure - invalid request", func(t *testing.T) {
		cmd := New(mockctx, &Config{})

		var b bytes.Buffer
		cmdErr := cmd.Connect(&b, bytes.NewBufferString("--"))
		require.Error(t, cmdErr)

		validateError(t, cmdErr, command.ValidationError, InvalidRequestErrorCode, "invalid character")
		require.Empty(t, b.Bytes())
	})

	t.Run("attempt to didconnect with invalid profile", func(t *testing.T) {
		cmd := New(mockctx, &Config{})

		request := &ConnectRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleUserID, Auth: sampleFakeTkn},
			Invitation: &outofbandClient.Invitation{},
			ConnectOpts: ConnectOpts{
				MyLabel: "sample-label",
			},
		}

		var b bytes.Buffer
		cmdErr := cmd.Connect(&b, getReader(t, &request))
		require.Error(t, cmdErr)

		validateError(t, cmdErr, command.ExecuteError, DIDConnectErrorCode, "failed to get VC wallet profile")
		require.Empty(t, b.Bytes())
	})
}

func TestCommand_ProposePresentation(t *testing.T) {
	const sampleDIDCommUser = "sample-didcomm-user02"

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	const (
		myDID    = "did:mydid:123"
		theirDID = "did:theirdid:123"
	)

	t.Run("successfully send propose presentation", func(t *testing.T) {
		sampleConnID := uuid.New().String()

		oobSvc := &mockoutofband.MockOobService{
			AcceptInvitationHandle: func(*outofbandSvc.Invitation, outofbandSvc.Options) (string, error) {
				return sampleConnID, nil
			},
		}
		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc

		didexSvc := &mockdidexchange.MockDIDExchangeSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:       service.PostState,
					StateID:    didexchange.StateIDCompleted,
					Properties: &mockdidexchange.MockEventProperties{ConnID: sampleConnID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[didexchange.DIDExchange] = didexSvc

		thID := uuid.New().String()
		ppSvc := &mockpresentproof.MockPresentProofSvc{
			ActionsFunc: func() ([]presentproofSvc.Action, error) {
				return []presentproofSvc.Action{
					{
						PIID: thID,
						Msg: service.NewDIDCommMsgMap(&presentproofSvc.RequestPresentationV2{
							Comment: "mock msg",
						}),
						MyDID:    myDID,
						TheirDID: theirDID,
					},
				}, nil
			},
			HandleFunc: func(service.DIDCommMsg) (string, error) {
				return thID, nil
			},
		}
		mockctx.ServiceMap[presentproofSvc.Name] = ppSvc

		store, err := mockctx.StorageProvider().OpenStore(connection.Namespace)
		require.NoError(t, err)

		record := &connection.Record{
			ConnectionID: sampleConnID,
			MyDID:        myDID,
			TheirDID:     theirDID,
		}
		recordBytes, err := json.Marshal(record)
		require.NoError(t, err)
		require.NoError(t, store.Put(fmt.Sprintf("conn_%s", sampleConnID), recordBytes))

		cmd := New(mockctx, &Config{})

		request := &ProposePresentationRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			Invitation: &wallet.GenericInvitation{},
		}

		var b bytes.Buffer
		cmdErr := cmd.ProposePresentation(&b, getReader(t, &request))
		require.NoError(t, cmdErr)

		var response ProposePresentationResponse
		require.NoError(t, json.NewDecoder(&b).Decode(&response))
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.PresentationRequest)
	})

	t.Run("failed to send propose presentation", func(t *testing.T) {
		oobSvc := &mockoutofband.MockOobService{
			AcceptInvitationHandle: func(*outofbandSvc.Invitation, outofbandSvc.Options) (string, error) {
				return "", fmt.Errorf(sampleCommandError)
			},
		}

		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc

		cmd := New(mockctx, &Config{})

		request := &ConnectRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			Invitation: &outofbandClient.Invitation{},
			ConnectOpts: ConnectOpts{
				MyLabel: "sample-label",
			},
		}

		var b bytes.Buffer
		cmdErr := cmd.ProposePresentation(&b, getReader(t, &request))
		require.Error(t, cmdErr)

		validateError(t, cmdErr, command.ExecuteError, ProposePresentationErrorCode, sampleCommandError)
		validateError(t, cmdErr, command.ExecuteError, ProposePresentationErrorCode, "failed to accept invitation")
		require.Empty(t, b.Bytes())
	})

	t.Run("failed to send propose presentation - invalid request", func(t *testing.T) {
		cmd := New(mockctx, &Config{})

		var b bytes.Buffer
		cmdErr := cmd.ProposePresentation(&b, bytes.NewBufferString("--"))
		require.Error(t, cmdErr)

		validateError(t, cmdErr, command.ValidationError, InvalidRequestErrorCode, "invalid character")
		require.Empty(t, b.Bytes())
	})

	t.Run("failed to send propose presentation - invalid profile", func(t *testing.T) {
		cmd := New(mockctx, &Config{})

		request := &ConnectRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleUserID, Auth: sampleFakeTkn},
			Invitation: &outofbandClient.Invitation{},
			ConnectOpts: ConnectOpts{
				MyLabel: "sample-label",
			},
		}

		var b bytes.Buffer
		cmdErr := cmd.ProposePresentation(&b, getReader(t, &request))
		require.Error(t, cmdErr)

		validateError(t, cmdErr, command.ExecuteError, ProposePresentationErrorCode, "failed to get VC wallet profile")
		require.Empty(t, b.Bytes())
	})
}

func TestCommand_PresentProof(t *testing.T) {
	const sampleDIDCommUser = "sample-didcomm-user03"

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	t.Run("successfully present proof", func(t *testing.T) {
		cmd := New(mockctx, &Config{})

		request := &PresentProofRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			ThreadID:     uuid.New().String(),
			Presentation: json.RawMessage{},
		}

		var b bytes.Buffer
		cmdErr := cmd.PresentProof(&b, getReader(t, &request))
		require.NoError(t, cmdErr)
	})

	t.Run("successfully present proof - wait for done", func(t *testing.T) {
		thID := uuid.New().String()
		mockPresentProofSvc := &mockpresentproof.MockPresentProofSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:    service.PostState,
					StateID: presentproofSvc.StateNameDone,
					Properties: &mockdidexchange.MockEventProperties{
						Properties: map[string]interface{}{
							webRedirectStatusKey: model.AckStatusOK,
							webRedirectURLKey:    exampleWebRedirect,
						},
					},
					Msg: &mockMsg{thID: thID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[presentproofSvc.Name] = mockPresentProofSvc

		cmd := New(mockctx, &Config{})

		request := &PresentProofRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			ThreadID:     thID,
			Presentation: json.RawMessage{},
			WaitForDone:  true,
			Timeout:      1 * time.Millisecond,
		}

		var b bytes.Buffer
		cmdErr := cmd.PresentProof(&b, getReader(t, &request))
		require.NoError(t, cmdErr)

		var response wallet.CredentialInteractionStatus
		require.NoError(t, json.NewDecoder(&b).Decode(&response))
		require.NotEmpty(t, response)
		require.Equal(t, exampleWebRedirect, response.RedirectURL)
		require.Equal(t, model.AckStatusOK, response.Status)
	})

	t.Run("failed to present proof", func(t *testing.T) {
		ppSvc := &mockpresentproof.MockPresentProofSvc{
			ActionContinueFunc: func(string, ...presentproofSvc.Opt) error {
				return fmt.Errorf(sampleCommandError)
			},
		}

		mockctx.ServiceMap[presentproofSvc.Name] = ppSvc

		cmd := New(mockctx, &Config{})

		request := &PresentProofRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			ThreadID:     uuid.New().String(),
			Presentation: json.RawMessage{},
		}

		var b bytes.Buffer
		cmdErr := cmd.PresentProof(&b, getReader(t, &request))
		validateError(t, cmdErr, command.ExecuteError, PresentProofErrorCode, sampleCommandError)
		require.Empty(t, b.Bytes())
	})

	t.Run("failed to present proof - invalid request", func(t *testing.T) {
		cmd := New(mockctx, &Config{})

		var b bytes.Buffer
		cmdErr := cmd.PresentProof(&b, bytes.NewBufferString("--"))
		require.Error(t, cmdErr)

		validateError(t, cmdErr, command.ValidationError, InvalidRequestErrorCode, "invalid character")
		require.Empty(t, b.Bytes())
	})

	t.Run("failed to present proof - invalid profile", func(t *testing.T) {
		cmd := New(mockctx, &Config{})

		request := &PresentProofRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleUserID, Auth: token},
			ThreadID:     uuid.New().String(),
			Presentation: json.RawMessage{},
		}

		var b bytes.Buffer
		cmdErr := cmd.PresentProof(&b, getReader(t, &request))
		require.Error(t, cmdErr)

		validateError(t, cmdErr, command.ExecuteError, PresentProofErrorCode, "failed to get VC wallet profile")
		require.Empty(t, b.Bytes())
	})
}

func TestCommand_ProposeCredential(t *testing.T) {
	const (
		sampleDIDCommUser = "sample-didcomm-user02"
		sampleMsgComment  = "sample mock msg"
		myDID             = "did:mydid:123"
		theirDID          = "did:theirdid:123"
	)

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	t.Run("successfully send propose credential", func(t *testing.T) {
		sampleConnID := uuid.New().String()

		oobSvc := &mockoutofband.MockOobService{
			AcceptInvitationHandle: func(*outofbandSvc.Invitation, outofbandSvc.Options) (string, error) {
				return sampleConnID, nil
			},
		}
		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc

		didexSvc := &mockdidexchange.MockDIDExchangeSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:       service.PostState,
					StateID:    didexchange.StateIDCompleted,
					Properties: &mockdidexchange.MockEventProperties{ConnID: sampleConnID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[didexchange.DIDExchange] = didexSvc

		thID := uuid.New().String()
		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			ActionsFunc: func() ([]issuecredentialsvc.Action, error) {
				return []issuecredentialsvc.Action{
					{
						PIID: thID,
						Msg: service.NewDIDCommMsgMap(&issuecredentialsvc.OfferCredentialV2{
							Comment: sampleMsgComment,
						}),
						MyDID:    myDID,
						TheirDID: theirDID,
					},
				}, nil
			},
			HandleFunc: func(service.DIDCommMsg) (string, error) {
				return thID, nil
			},
		}
		mockctx.ServiceMap[issuecredentialsvc.Name] = icSvc

		store, err := mockctx.StorageProvider().OpenStore(connection.Namespace)
		require.NoError(t, err)

		record := &connection.Record{
			ConnectionID: sampleConnID,
			MyDID:        myDID,
			TheirDID:     theirDID,
		}
		recordBytes, err := json.Marshal(record)
		require.NoError(t, err)
		require.NoError(t, store.Put(fmt.Sprintf("conn_%s", sampleConnID), recordBytes))

		cmd := New(mockctx, &Config{})

		request := &ProposeCredentialRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			Invitation: &wallet.GenericInvitation{},
		}

		var b bytes.Buffer
		cmdErr := cmd.ProposeCredential(&b, getReader(t, &request))
		require.NoError(t, cmdErr)

		var response ProposeCredentialResponse
		require.NoError(t, json.NewDecoder(&b).Decode(&response))
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.OfferCredential)

		offer := &issuecredentialsvc.OfferCredentialV2{}

		err = response.OfferCredential.Decode(offer)
		require.NoError(t, err)
		require.NotEmpty(t, offer)
		require.Equal(t, sampleMsgComment, offer.Comment)
	})

	t.Run("failed to send propose credential", func(t *testing.T) {
		oobSvc := &mockoutofband.MockOobService{
			AcceptInvitationHandle: func(*outofbandSvc.Invitation, outofbandSvc.Options) (string, error) {
				return "", fmt.Errorf(sampleCommandError)
			},
		}

		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc

		cmd := New(mockctx, &Config{})

		request := &ConnectRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			Invitation: &outofbandClient.Invitation{},
			ConnectOpts: ConnectOpts{
				MyLabel: "sample-label",
			},
		}

		var b bytes.Buffer
		cmdErr := cmd.ProposeCredential(&b, getReader(t, &request))
		require.Error(t, cmdErr)

		validateError(t, cmdErr, command.ExecuteError, ProposeCredentialErrorCode, sampleCommandError)
		validateError(t, cmdErr, command.ExecuteError, ProposeCredentialErrorCode, "failed to accept invitation")
		require.Empty(t, b.Bytes())
	})

	t.Run("failed to send propose credential - invalid request", func(t *testing.T) {
		cmd := New(mockctx, &Config{})

		var b bytes.Buffer
		cmdErr := cmd.ProposeCredential(&b, bytes.NewBufferString("--"))
		require.Error(t, cmdErr)

		validateError(t, cmdErr, command.ValidationError, InvalidRequestErrorCode, "invalid character")
		require.Empty(t, b.Bytes())
	})

	t.Run("failed to send propose credential - invalid profile", func(t *testing.T) {
		cmd := New(mockctx, &Config{})

		request := &ConnectRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: sampleUserID, Auth: sampleFakeTkn},
			Invitation: &outofbandClient.Invitation{},
			ConnectOpts: ConnectOpts{
				MyLabel: "sample-label",
			},
		}

		var b bytes.Buffer
		cmdErr := cmd.ProposeCredential(&b, getReader(t, &request))
		require.Error(t, cmdErr)

		validateError(t, cmdErr, command.ExecuteError, ProposeCredentialErrorCode, "failed to get VC wallet profile")
		require.Empty(t, b.Bytes())
	})
}

func TestCommand_RequestCredential(t *testing.T) {
	const sampleDIDCommUser = "sample-didcomm-user03"

	mockctx := newMockProvider(t)

	createSampleUserProfile(t, mockctx, &vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	token, lock := unlockWallet(t, mockctx, &vcwallet.UnlockWalletRequest{
		UserID:             sampleDIDCommUser,
		LocalKMSPassphrase: samplePassPhrase,
	})

	defer lock()

	t.Run("successfully request credential", func(t *testing.T) {
		cmd := New(mockctx, &Config{})

		request := &RequestCredentialRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			ThreadID:     uuid.New().String(),
			Presentation: json.RawMessage{},
		}

		var b bytes.Buffer
		cmdErr := cmd.RequestCredential(&b, getReader(t, &request))
		require.NoError(t, cmdErr)
	})

	t.Run("successfully request credential - wait for done", func(t *testing.T) {
		thID := uuid.New().String()

		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:    service.PostState,
					StateID: "done",
					Properties: &mockdidexchange.MockEventProperties{
						Properties: map[string]interface{}{
							webRedirectStatusKey: model.AckStatusOK,
							webRedirectURLKey:    exampleWebRedirect,
						},
					},
					Msg: &mockMsg{thID: thID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[issuecredentialsvc.Name] = icSvc

		cmd := New(mockctx, &Config{})

		request := &RequestCredentialRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			ThreadID:     thID,
			Presentation: json.RawMessage{},
			WaitForDone:  true,
			Timeout:      600 * time.Millisecond,
		}

		var b bytes.Buffer
		cmdErr := cmd.RequestCredential(&b, getReader(t, &request))
		require.NoError(t, cmdErr)

		var response wallet.CredentialInteractionStatus
		require.NoError(t, json.NewDecoder(&b).Decode(&response))
		require.NotEmpty(t, response)
		require.Equal(t, exampleWebRedirect, response.RedirectURL)
		require.Equal(t, model.AckStatusOK, response.Status)
	})

	t.Run("failed to request credential", func(t *testing.T) {
		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			ActionContinueFunc: func(string, ...issuecredentialsvc.Opt) error {
				return fmt.Errorf(sampleCommandError)
			},
		}
		mockctx.ServiceMap[issuecredentialsvc.Name] = icSvc

		cmd := New(mockctx, &Config{})

		request := &RequestCredentialRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleDIDCommUser, Auth: token},
			ThreadID:     uuid.New().String(),
			Presentation: json.RawMessage{},
		}

		var b bytes.Buffer
		cmdErr := cmd.RequestCredential(&b, getReader(t, &request))
		validateError(t, cmdErr, command.ExecuteError, RequestCredentialErrorCode, sampleCommandError)
		require.Empty(t, b.Bytes())
	})

	t.Run("failed to request credential - invalid request", func(t *testing.T) {
		cmd := New(mockctx, &Config{})

		var b bytes.Buffer
		cmdErr := cmd.RequestCredential(&b, bytes.NewBufferString("--"))
		require.Error(t, cmdErr)

		validateError(t, cmdErr, command.ValidationError, InvalidRequestErrorCode, "invalid character")
		require.Empty(t, b.Bytes())
	})

	t.Run("failed to request credential - invalid profile", func(t *testing.T) {
		cmd := New(mockctx, &Config{})

		request := &RequestCredentialRequest{
			WalletAuth:   vcwallet.WalletAuth{UserID: sampleUserID, Auth: token},
			ThreadID:     uuid.New().String(),
			Presentation: json.RawMessage{},
		}

		var b bytes.Buffer
		cmdErr := cmd.RequestCredential(&b, getReader(t, &request))
		require.Error(t, cmdErr)

		validateError(t, cmdErr, command.ExecuteError, RequestCredentialErrorCode, "failed to get VC wallet profile")
		require.Empty(t, b.Bytes())
	})
}

func createSampleUserProfile(t *testing.T, ctx *mockprovider.Provider, request *vcwallet.CreateOrUpdateProfileRequest) {
	cmd := vcwallet.New(ctx, &Config{})
	require.NotNil(t, cmd)

	var l bytes.Buffer
	cmdErr := cmd.CreateProfile(&l, getReader(t, request))
	require.NoError(t, cmdErr)
}

func getReader(t *testing.T, v interface{}) io.Reader {
	vcReqBytes, err := json.Marshal(v)
	require.NoError(t, err)

	return bytes.NewBuffer(vcReqBytes)
}

func getUnlockToken(t *testing.T, b bytes.Buffer) string {
	var response vcwallet.UnlockWalletResponse

	require.NoError(t, json.NewDecoder(&b).Decode(&response))

	return response.Token
}

func unlockWallet(t *testing.T, ctx *mockprovider.Provider, request *vcwallet.UnlockWalletRequest) (string, func()) {
	cmd := vcwallet.New(ctx, nil)

	var b bytes.Buffer

	cmdErr := cmd.Open(&b, getReader(t, &request))
	require.NoError(t, cmdErr)

	return getUnlockToken(t, b), func() {
		cmdErr = cmd.Close(&b, getReader(t, &vcwallet.LockWalletRequest{UserID: request.UserID}))
		if cmdErr != nil {
			t.Log(t, cmdErr)
		}
	}
}

func validateError(t *testing.T, err command.Error,
	expectedType command.Type, expectedCode command.Code, contains string) {
	require.Error(t, err)
	require.Equal(t, err.Type(), expectedType)
	require.Equal(t, err.Code(), expectedCode)

	if contains != "" {
		require.Contains(t, err.Error(), contains)
	}
}

func newMockProvider(t *testing.T) *mockprovider.Provider {
	t.Helper()

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	serviceMap := map[string]interface{}{
		presentproofSvc.Name:    &mockpresentproof.MockPresentProofSvc{},
		outofbandSvc.Name:       &mockoutofband.MockOobService{},
		didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{},
		mediator.Coordination:   &mockmediator.MockMediatorSvc{},
		issuecredentialsvc.Name: &mockissuecredential.MockIssueCredentialSvc{},
		oobv2.Name:              &mockoutofbandv2.MockOobService{},
	}

	return &mockprovider.Provider{
		StorageProviderValue:              mockstorage.NewMockStoreProvider(),
		ProtocolStateStorageProviderValue: mockstorage.NewMockStoreProvider(),
		DocumentLoaderValue:               loader,
		ServiceMap:                        serviceMap,
	}
}

// mockMsg containing custom parent thread ID.
type mockMsg struct {
	*service.DIDCommMsgMap
	thID string
}

func (m *mockMsg) ParentThreadID() string {
	return m.thID
}

func (m *mockMsg) ThreadID() (string, error) {
	return m.thID, nil
}
