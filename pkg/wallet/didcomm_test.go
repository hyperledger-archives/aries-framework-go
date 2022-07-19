/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	issuecredentialsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	outofbandSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	oobv2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	presentproofSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
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
)

const (
	exampleWebRedirect = "http://example.com/sample"
	sampleMsgComment   = "sample mock msg"
)

func TestNewDidComm(t *testing.T) {
	t.Run("test get wallet failure - present proof client initialize error", func(t *testing.T) {
		mockctx := newDidCommMockProvider(t)
		delete(mockctx.ServiceMap, presentproofSvc.Name)

		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.Error(t, err)
		require.Empty(t, didcomm)

		require.Contains(t, err.Error(), "failed to initialize present proof client")
	})

	t.Run("test get wallet failure - oob client initialize error", func(t *testing.T) {
		mockctx := newDidCommMockProvider(t)
		delete(mockctx.ServiceMap, outofbandSvc.Name)

		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.Error(t, err)
		require.Empty(t, didcomm)
		require.Contains(t, err.Error(), "failed to initialize out-of-band client")
	})

	t.Run("test get wallet failure - oob client initialize error", func(t *testing.T) {
		mockctx := newDidCommMockProvider(t)
		delete(mockctx.ServiceMap, didexchange.DIDExchange)

		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.Error(t, err)
		require.Empty(t, didcomm)
		require.Contains(t, err.Error(), "failed to initialize didexchange client")
	})

	t.Run("test get wallet failure - connection lookup initialize error", func(t *testing.T) {
		mockctx := newDidCommMockProvider(t)
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.FailNamespace = "didexchange"
		mockctx.StorageProviderValue = mockStoreProvider

		err := CreateProfile(sampleUserID, mockctx, WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		wallet, err := New(sampleUserID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.Error(t, err)
		require.Empty(t, didcomm)
		require.Contains(t, err.Error(), "failed to initialize connection lookup")
	})
}

func TestWallet_Connect(t *testing.T) {
	sampleDIDCommUser := uuid.New().String()
	mockctx := newDidCommMockProvider(t)
	err := CreateProfile(sampleDIDCommUser, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	t.Run("test did connect success", func(t *testing.T) {
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

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		connectionID, err := didcomm.Connect(token, &outofband.Invitation{})
		require.NoError(t, err)
		require.Equal(t, sampleConnID, connectionID)
	})

	t.Run("test did connect failure - accept invitation failure", func(t *testing.T) {
		oobSvc := &mockoutofband.MockOobService{
			AcceptInvitationHandle: func(*outofbandSvc.Invitation, outofbandSvc.Options) (string, error) {
				return "", fmt.Errorf(sampleWalletErr)
			},
		}

		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		connectionID, err := didcomm.Connect(token, &outofband.Invitation{}, WithConnectTimeout(1*time.Millisecond))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)
		require.Contains(t, err.Error(), "failed to accept invitation")
		require.Empty(t, connectionID)
	})

	t.Run("test did connect failure - register event failure", func(t *testing.T) {
		didexSvc := &mockdidexchange.MockDIDExchangeSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				return fmt.Errorf(sampleWalletErr)
			},
		}
		mockctx.ServiceMap[didexchange.DIDExchange] = didexSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		connectionID, err := didcomm.Connect(token, &outofband.Invitation{}, WithConnectTimeout(1*time.Millisecond))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)
		require.Contains(t, err.Error(), "failed to register msg event")
		require.Empty(t, connectionID)
	})

	t.Run("test did connect failure - state not completed", func(t *testing.T) {
		mockctx.ServiceMap[outofbandSvc.Name] = &mockoutofband.MockOobService{}
		mockctx.ServiceMap[didexchange.DIDExchange] = &mockdidexchange.MockDIDExchangeSvc{}

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		connectionID, err := didcomm.Connect(token, &outofband.Invitation{}, WithConnectTimeout(1*time.Millisecond))
		require.Error(t, err)
		require.Contains(t, err.Error(), "time out waiting for did exchange state 'completed'")
		require.Empty(t, connectionID)
	})

	t.Run("test did connect success - with warnings", func(t *testing.T) {
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
					Type:    service.PreState,
					StateID: didexchange.StateIDCompleted,
				}

				ch <- service.StateMsg{
					Type:    service.PostState,
					StateID: didexchange.StateIDCompleted,
				}

				ch <- service.StateMsg{
					Type:       service.PostState,
					StateID:    didexchange.StateIDCompleted,
					Properties: &mockdidexchange.MockEventProperties{ConnID: sampleConnID},
				}

				return nil
			},
			UnregisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				return fmt.Errorf(sampleWalletErr)
			},
		}
		mockctx.ServiceMap[didexchange.DIDExchange] = didexSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		connectionID, err := didcomm.Connect(token, &outofband.Invitation{})
		require.NoError(t, err)
		require.Equal(t, sampleConnID, connectionID)
	})

	t.Run("test oob connect options", func(t *testing.T) {
		options := []ConnectOptions{
			WithConnectTimeout(10 * time.Second),
			WithRouterConnections("sample-conn"),
			WithMyLabel("sample-label"),
			WithReuseAnyConnection(true),
			WithReuseDID("sample-did"),
		}

		opts := &connectOpts{}
		for _, opt := range options {
			opt(opts)
		}

		require.Equal(t, opts.timeout, 10*time.Second)
		require.Equal(t, opts.Connections[0], "sample-conn")
		require.Equal(t, opts.MyLabel(), "sample-label")
		require.Equal(t, opts.ReuseDID, "sample-did")
		require.True(t, opts.ReuseAny)

		require.Len(t, getOobMessageOptions(opts), 3)
	})
}

func TestWallet_ProposePresentation(t *testing.T) {
	sampleDIDCommUser := uuid.New().String()
	mockctx := newDidCommMockProvider(t)
	err := CreateProfile(sampleDIDCommUser, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	const (
		myDID    = "did:mydid:123"
		theirDID = "did:theirdid:123"
	)

	t.Run("test propose presentation success - didcomm v1", func(t *testing.T) {
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

		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc
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

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		invitation := GenericInvitation{}
		err = json.Unmarshal([]byte(`{
			"@id": "abc123",
			"@type": "https://didcomm.org/out-of-band/1.0/invitation"
		}`), &invitation)
		require.NoError(t, err)

		msg, err := didcomm.ProposePresentation(token, &invitation,
			WithConnectOptions(WithConnectTimeout(1*time.Millisecond)))
		require.NoError(t, err)
		require.NotEmpty(t, msg)

		// empty invitation defaults to DIDComm v1
		msg, err = didcomm.ProposePresentation(token, &GenericInvitation{},
			WithConnectOptions(WithConnectTimeout(1*time.Millisecond)))
		require.NoError(t, err)
		require.NotEmpty(t, msg)

		// invitation with unknown version defaults to DIDComm v1
		msg, err = didcomm.ProposePresentation(token, &GenericInvitation{version: "unknown"},
			WithConnectOptions(WithConnectTimeout(1*time.Millisecond)))
		require.NoError(t, err)
		require.NotEmpty(t, msg)
	})

	t.Run("test propose presentation success - didcomm v2", func(t *testing.T) {
		sampleConnID := uuid.New().String()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		oobv2Svc := mockoutofbandv2.NewMockOobService(ctrl)
		oobv2Svc.EXPECT().AcceptInvitation(gomock.Any(), gomock.Any()).Return(sampleConnID, nil).AnyTimes()

		mockctx.ServiceMap[oobv2.Name] = oobv2Svc

		thID := uuid.New().String()

		ppSvc := &mockpresentproof.MockPresentProofSvc{
			ActionsFunc: func() ([]presentproofSvc.Action, error) {
				return []presentproofSvc.Action{
					{
						PIID: thID,
						Msg: service.NewDIDCommMsgMap(&presentproofSvc.RequestPresentationV3{
							Body: presentproofSvc.RequestPresentationV3Body{
								Comment: "mock msg",
							},
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

		connRec, err := connection.NewRecorder(mockctx)
		require.NoError(t, err)

		record := &connection.Record{
			ConnectionID:   sampleConnID,
			MyDID:          myDID,
			TheirDID:       theirDID,
			DIDCommVersion: service.V2,
			State:          connection.StateNameCompleted,
		}

		err = connRec.SaveConnectionRecord(record)
		require.NoError(t, err)

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		invitation := GenericInvitation{}
		err = json.Unmarshal([]byte(`{
			"id": "abc123",
			"type": "https://didcomm.org/out-of-band/2.0/invitation"
		}`), &invitation)
		require.NoError(t, err)

		msg, err := didcomm.ProposePresentation(token, &invitation,
			WithConnectOptions(WithConnectTimeout(1*time.Millisecond)))
		require.NoError(t, err)
		require.NotEmpty(t, msg)
	})

	t.Run("test propose presentation failure - did connect failure", func(t *testing.T) {
		didexSvc := &mockdidexchange.MockDIDExchangeSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				return fmt.Errorf(sampleWalletErr)
			},
		}
		mockctx.ServiceMap[didexchange.DIDExchange] = didexSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		msg, err := didcomm.ProposePresentation(token, &GenericInvitation{})
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)
		require.Contains(t, err.Error(), "failed to perform did connection")
		require.Empty(t, msg)
	})

	t.Run("test propose presentation failure - no connection found", func(t *testing.T) {
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

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		msg, err := didcomm.ProposePresentation(token, &GenericInvitation{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to lookup connection")
		require.Empty(t, msg)
	})

	t.Run("test propose presentation failure - failed to send", func(t *testing.T) {
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

		ppSvc := &mockpresentproof.MockPresentProofSvc{
			HandleFunc: func(service.DIDCommMsg) (string, error) {
				return "", fmt.Errorf(sampleWalletErr)
			},
			HandleOutboundFunc: func(service.DIDCommMsg, string, string) (string, error) {
				return "", fmt.Errorf(sampleWalletErr)
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

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		msg, err := didcomm.ProposePresentation(token, &GenericInvitation{})
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)
		require.Contains(t, err.Error(), "failed to propose presentation from wallet")
		require.Empty(t, msg)
	})

	t.Run("test propose presentation failure - timeout waiting for presentation request", func(t *testing.T) {
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

		ppSvc := &mockpresentproof.MockPresentProofSvc{
			HandleFunc: func(service.DIDCommMsg) (string, error) {
				return uuid.New().String(), nil
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

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		msg, err := didcomm.ProposePresentation(token, &GenericInvitation{}, WithInitiateTimeout(600*time.Millisecond))
		require.Error(t, err)
		require.Contains(t, err.Error(), "timeout waiting for request presentation message")
		require.Empty(t, msg)
	})

	t.Run("test propose presentation failure - action error", func(t *testing.T) {
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

		ppSvc := &mockpresentproof.MockPresentProofSvc{
			HandleFunc: func(service.DIDCommMsg) (string, error) {
				return uuid.New().String(), nil
			},
			ActionsFunc: func() ([]presentproofSvc.Action, error) {
				return nil, fmt.Errorf(sampleWalletErr)
			},
		}
		mockctx.ServiceMap[presentproofSvc.Name] = ppSvc

		store, err := mockctx.StorageProvider().OpenStore(connection.Namespace)
		require.NoError(t, err)

		record := &connection.Record{
			ConnectionID: sampleConnID,
			TheirDID:     theirDID,
		}
		recordBytes, err := json.Marshal(record)
		require.NoError(t, err)
		require.NoError(t, store.Put(fmt.Sprintf("conn_%s", sampleConnID), recordBytes))

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		msg, err := didcomm.ProposePresentation(token, &GenericInvitation{}, WithInitiateTimeout(1*time.Millisecond),
			WithFromDID("did:sample:from"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "timeout waiting for request presentation message")
		require.Empty(t, msg)
	})

	t.Run("test propose presentation failure - oob v2 accept error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expectErr := fmt.Errorf("expected error")

		oobv2Svc := mockoutofbandv2.NewMockOobService(ctrl)
		oobv2Svc.EXPECT().AcceptInvitation(gomock.Any(), gomock.Any()).Return("", expectErr).AnyTimes()

		mockctx.ServiceMap[oobv2.Name] = oobv2Svc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		invitation := GenericInvitation{}
		err = json.Unmarshal([]byte(`{
			"id": "abc123",
			"type": "https://didcomm.org/out-of-band/2.0/invitation"
		}`), &invitation)
		require.NoError(t, err)

		_, err = didcomm.ProposePresentation(token, &invitation,
			WithConnectOptions(WithConnectTimeout(1*time.Millisecond)))
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
		require.Contains(t, err.Error(), "failed to accept OOB v2 invitation")
	})
}

func TestWallet_PresentProof(t *testing.T) {
	sampleDIDCommUser := uuid.New().String()
	mockctx := newDidCommMockProvider(t)
	err := CreateProfile(sampleDIDCommUser, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	t.Run("test present proof success", func(t *testing.T) {
		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.PresentProof(token, uuid.New().String(), FromPresentation(&verifiable.Presentation{}))
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.Equal(t, model.AckStatusPENDING, response.Status)
	})

	t.Run("test present proof success - wait for done with redirect", func(t *testing.T) {
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

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.PresentProof(token, thID, FromPresentation(&verifiable.Presentation{}),
			WaitForDone(1*time.Millisecond))
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.Equal(t, model.AckStatusOK, response.Status)
		require.Equal(t, exampleWebRedirect, response.RedirectURL)
	})

	t.Run("test present proof success - wait for abandoned with redirect", func(t *testing.T) {
		thID := uuid.New().String()
		mockPresentProofSvc := &mockpresentproof.MockPresentProofSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:    service.PostState,
					StateID: presentproofSvc.StateNameAbandoned,
					Properties: &mockdidexchange.MockEventProperties{
						Properties: map[string]interface{}{
							webRedirectStatusKey: model.AckStatusFAIL,
							webRedirectURLKey:    exampleWebRedirect,
						},
					},
					Msg: &mockMsg{thID: thID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[presentproofSvc.Name] = mockPresentProofSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.PresentProof(token, thID, FromPresentation(&verifiable.Presentation{}),
			WaitForDone(1*time.Millisecond))
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.Equal(t, model.AckStatusFAIL, response.Status)
		require.Equal(t, exampleWebRedirect, response.RedirectURL)
	})

	t.Run("test present proof success - wait for done no redirect", func(t *testing.T) {
		thID := uuid.New().String()
		mockPresentProofSvc := &mockpresentproof.MockPresentProofSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:       service.PostState,
					StateID:    presentproofSvc.StateNameDone,
					Properties: &mockdidexchange.MockEventProperties{},
					Msg:        &mockMsg{thID: thID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[presentproofSvc.Name] = mockPresentProofSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.PresentProof(token, thID, FromPresentation(&verifiable.Presentation{}),
			WaitForDone(1*time.Millisecond))
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.Equal(t, model.AckStatusOK, response.Status)
		require.Empty(t, response.RedirectURL)
	})

	t.Run("test present proof failure - wait for abandoned no redirect", func(t *testing.T) {
		thID := uuid.New().String()
		mockPresentProofSvc := &mockpresentproof.MockPresentProofSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:       service.PostState,
					StateID:    presentproofSvc.StateNameAbandoned,
					Properties: &mockdidexchange.MockEventProperties{},
					Msg:        &mockMsg{thID: thID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[presentproofSvc.Name] = mockPresentProofSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.PresentProof(token, thID, FromPresentation(&verifiable.Presentation{}),
			WaitForDone(1*time.Millisecond))
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.Equal(t, model.AckStatusFAIL, response.Status)
		require.Empty(t, response.RedirectURL)
	})

	t.Run("test present proof failure", func(t *testing.T) {
		ppSvc := &mockpresentproof.MockPresentProofSvc{
			ActionContinueFunc: func(string, ...presentproofSvc.Opt) error {
				return fmt.Errorf(sampleWalletErr)
			},
		}

		mockctx.ServiceMap[presentproofSvc.Name] = ppSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.PresentProof(token, uuid.New().String(), FromRawPresentation([]byte("{}")))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)
		require.Empty(t, response)
	})

	t.Run("test present proof failure - failed to register message event", func(t *testing.T) {
		thID := uuid.New().String()
		mockPresentProofSvc := &mockpresentproof.MockPresentProofSvc{
			RegisterMsgEventErr: errors.New(sampleWalletErr),
		}
		mockctx.ServiceMap[presentproofSvc.Name] = mockPresentProofSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.PresentProof(token, thID, FromPresentation(&verifiable.Presentation{}),
			WaitForDone(1*time.Millisecond))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)
		require.Empty(t, response)
	})

	t.Run("test present proof failure - wait for done timeout", func(t *testing.T) {
		thID := uuid.New().String()
		mockPresentProofSvc := &mockpresentproof.MockPresentProofSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type: service.PreState,
				}

				ch <- service.StateMsg{
					Type: service.PostState,
				}

				ch <- service.StateMsg{
					Type: service.PostState,
					Msg:  &mockMsg{thID: "invalid"},
				}

				ch <- service.StateMsg{
					Type:    service.PostState,
					StateID: "invalid",
					Msg:     &mockMsg{thID: thID, fail: errors.New(sampleWalletErr)},
				}

				ch <- service.StateMsg{
					Type:    service.PostState,
					StateID: "invalid",
					Msg:     &mockMsg{thID: thID},
				}

				return nil
			},
			UnregisterMsgEventErr: errors.New(sampleWalletErr),
		}
		mockctx.ServiceMap[presentproofSvc.Name] = mockPresentProofSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.PresentProof(token, thID, FromPresentation(&verifiable.Presentation{}),
			WaitForDone(1*time.Millisecond))
		require.Error(t, err)
		require.Contains(t, err.Error(), "time out waiting for credential interaction to get completed")
		require.Empty(t, response)
	})
}

func TestWallet_ProposeCredential(t *testing.T) {
	sampleDIDCommUser := uuid.New().String()
	mockctx := newDidCommMockProvider(t)
	err := CreateProfile(sampleDIDCommUser, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	const (
		myDID    = "did:mydid:123"
		theirDID = "did:theirdid:123"
	)

	t.Run("test propose credential success", func(t *testing.T) {
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

		mockctx.ServiceMap[outofbandSvc.Name] = oobSvc
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

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		msg, err := didcomm.ProposeCredential(token, &GenericInvitation{},
			WithConnectOptions(WithConnectTimeout(1*time.Millisecond)))
		require.NoError(t, err)
		require.NotEmpty(t, msg)

		offer := &issuecredentialsvc.OfferCredentialV2{}

		err = msg.Decode(offer)
		require.NoError(t, err)
		require.NotEmpty(t, offer)
		require.Equal(t, sampleMsgComment, offer.Comment)
	})

	t.Run("test propose credential failure - did connect failure", func(t *testing.T) {
		didexSvc := &mockdidexchange.MockDIDExchangeSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				return fmt.Errorf(sampleWalletErr)
			},
		}
		mockctx.ServiceMap[didexchange.DIDExchange] = didexSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		msg, err := didcomm.ProposeCredential(token, &GenericInvitation{})
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)
		require.Contains(t, err.Error(), "failed to perform did connection")
		require.Empty(t, msg)
	})

	t.Run("test propose credential failure - oobv2 accept error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expectErr := fmt.Errorf("expected error")

		oobv2Svc := mockoutofbandv2.NewMockOobService(ctrl)
		oobv2Svc.EXPECT().AcceptInvitation(gomock.Any(), gomock.Any()).Return("", expectErr).AnyTimes()

		mockctx.ServiceMap[oobv2.Name] = oobv2Svc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		invitation := GenericInvitation{}
		err = json.Unmarshal([]byte(`{
			"id": "abc123",
			"type": "https://didcomm.org/out-of-band/2.0/invitation"
		}`), &invitation)
		require.NoError(t, err)

		_, err = didcomm.ProposeCredential(token, &invitation,
			WithConnectOptions(WithConnectTimeout(1*time.Millisecond)))
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
		require.Contains(t, err.Error(), "failed to accept OOB v2 invitation")
	})

	t.Run("test propose credential failure - no connection found", func(t *testing.T) {
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

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		msg, err := didcomm.ProposeCredential(token, &GenericInvitation{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to lookup connection")
		require.Empty(t, msg)
	})

	t.Run("test propose credential failure - failed to send", func(t *testing.T) {
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

		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			HandleFunc: func(service.DIDCommMsg) (string, error) {
				return "", fmt.Errorf(sampleWalletErr)
			},
			HandleOutboundFunc: func(service.DIDCommMsg, string, string) (string, error) {
				return "", fmt.Errorf(sampleWalletErr)
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

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		msg, err := didcomm.ProposeCredential(token, &GenericInvitation{})
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)
		require.Contains(t, err.Error(), "failed to propose credential from wallet")
		require.Empty(t, msg)
	})

	t.Run("test propose credential failure - timeout waiting for offer credential msg", func(t *testing.T) {
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

		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			HandleFunc: func(service.DIDCommMsg) (string, error) {
				return uuid.New().String(), nil
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

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		msg, err := didcomm.ProposeCredential(token, &GenericInvitation{}, WithInitiateTimeout(600*time.Millisecond))
		require.Error(t, err)
		require.Contains(t, err.Error(), "timeout waiting for offer credential message")
		require.Empty(t, msg)
	})

	t.Run("test propose presentation failure - action error", func(t *testing.T) {
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

		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			HandleFunc: func(service.DIDCommMsg) (string, error) {
				return uuid.New().String(), nil
			},
			ActionsFunc: func() ([]issuecredentialsvc.Action, error) {
				return nil, fmt.Errorf(sampleWalletErr)
			},
		}
		mockctx.ServiceMap[issuecredentialsvc.Name] = icSvc

		store, err := mockctx.StorageProvider().OpenStore(connection.Namespace)
		require.NoError(t, err)

		record := &connection.Record{
			ConnectionID: sampleConnID,
			TheirDID:     theirDID,
		}
		recordBytes, err := json.Marshal(record)
		require.NoError(t, err)
		require.NoError(t, store.Put(fmt.Sprintf("conn_%s", sampleConnID), recordBytes))

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		msg, err := didcomm.ProposeCredential(token, &GenericInvitation{}, WithInitiateTimeout(1*time.Millisecond),
			WithFromDID("did:sample:from"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "timeout waiting for offer credential message")
		require.Empty(t, msg)
	})
}

func TestWallet_RequestCredential(t *testing.T) {
	sampleDIDCommUser := uuid.New().String()
	mockctx := newDidCommMockProvider(t)
	err := CreateProfile(sampleDIDCommUser, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	t.Run("test request credential success", func(t *testing.T) {
		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.RequestCredential(token, uuid.New().String(), FromPresentation(&verifiable.Presentation{}))
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.Equal(t, model.AckStatusPENDING, response.Status)
	})

	t.Run("test request credential success - wait for done with redirect", func(t *testing.T) {
		thID := uuid.New().String()

		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:    service.PostState,
					StateID: stateNameDone,
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

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.RequestCredential(token, thID, FromPresentation(&verifiable.Presentation{}),
			WaitForDone(0))
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.Equal(t, model.AckStatusOK, response.Status)
		require.Equal(t, exampleWebRedirect, response.RedirectURL)
	})

	t.Run("test for request credential - wait for problem report with redirect", func(t *testing.T) {
		thID := uuid.New().String()

		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:    service.PostState,
					StateID: stateNameAbandoned,
					Properties: &mockdidexchange.MockEventProperties{
						Properties: map[string]interface{}{
							webRedirectStatusKey: model.AckStatusFAIL,
							webRedirectURLKey:    exampleWebRedirect,
						},
					},
					Msg: &mockMsg{thID: thID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[issuecredentialsvc.Name] = icSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.RequestCredential(token, thID, FromPresentation(&verifiable.Presentation{}),
			WaitForDone(1*time.Millisecond))
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.Equal(t, model.AckStatusFAIL, response.Status)
		require.Equal(t, exampleWebRedirect, response.RedirectURL)
	})

	t.Run("test request credential success - wait for done no redirect", func(t *testing.T) {
		thID := uuid.New().String()

		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:       service.PostState,
					StateID:    stateNameDone,
					Properties: &mockdidexchange.MockEventProperties{},
					Msg:        &mockMsg{thID: thID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[issuecredentialsvc.Name] = icSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.RequestCredential(token, thID, FromPresentation(&verifiable.Presentation{}),
			WaitForDone(10*time.Millisecond))
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.Equal(t, model.AckStatusOK, response.Status)
		require.Empty(t, response.RedirectURL)
	})

	t.Run("test request credential failure - wait for problem report no redirect", func(t *testing.T) {
		thID := uuid.New().String()

		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type:       service.PostState,
					StateID:    stateNameAbandoned,
					Properties: &mockdidexchange.MockEventProperties{},
					Msg:        &mockMsg{thID: thID},
				}

				return nil
			},
		}
		mockctx.ServiceMap[issuecredentialsvc.Name] = icSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.RequestCredential(token, thID, FromPresentation(&verifiable.Presentation{}),
			WaitForDone(1*time.Millisecond))
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.Equal(t, model.AckStatusFAIL, response.Status)
		require.Empty(t, response.RedirectURL)
	})

	t.Run("test request credential failure", func(t *testing.T) {
		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			ActionContinueFunc: func(string, ...issuecredentialsvc.Opt) error {
				return fmt.Errorf(sampleWalletErr)
			},
		}
		mockctx.ServiceMap[issuecredentialsvc.Name] = icSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.RequestCredential(token, uuid.New().String(), FromRawPresentation([]byte("{}")))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)
		require.Empty(t, response)
	})

	t.Run("test request credential failure - failed to register msg event", func(t *testing.T) {
		thID := uuid.New().String()
		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			RegisterMsgEventErr: errors.New(sampleWalletErr),
		}
		mockctx.ServiceMap[issuecredentialsvc.Name] = icSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.RequestCredential(token, thID, FromPresentation(&verifiable.Presentation{}),
			WaitForDone(1*time.Millisecond))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleWalletErr)
		require.Empty(t, response)
	})

	t.Run("test request credential success - wait for done timeout", func(t *testing.T) {
		thID := uuid.New().String()

		icSvc := &mockissuecredential.MockIssueCredentialSvc{
			RegisterMsgEventHandle: func(ch chan<- service.StateMsg) error {
				ch <- service.StateMsg{
					Type: service.PreState,
				}

				ch <- service.StateMsg{
					Type: service.PostState,
				}

				ch <- service.StateMsg{
					Type: service.PostState,
					Msg:  &mockMsg{thID: "invalid"},
				}

				ch <- service.StateMsg{
					Type:    service.PostState,
					StateID: "invalid",
					Msg:     &mockMsg{thID: thID, fail: errors.New(sampleWalletErr)},
				}

				ch <- service.StateMsg{
					Type:    service.PostState,
					StateID: "invalid",
					Msg:     &mockMsg{thID: thID},
				}

				return nil
			},
			UnregisterMsgEventErr: errors.New(sampleWalletErr),
		}
		mockctx.ServiceMap[issuecredentialsvc.Name] = icSvc

		wallet, err := New(sampleDIDCommUser, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, wallet)

		didcomm, err := NewDidComm(wallet, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, didcomm)

		token, err := wallet.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, token)

		defer wallet.Close()

		response, err := didcomm.RequestCredential(token, thID, FromPresentation(&verifiable.Presentation{}),
			WaitForDone(700*time.Millisecond))
		require.Error(t, err)
		require.Contains(t, err.Error(), "time out waiting for credential interaction to get completed")
		require.Empty(t, response)
	})
}

func newDidCommMockProvider(t *testing.T) *mockprovider.Provider {
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
	thID    string
	fail    error
	msgType string
}

func (m *mockMsg) ParentThreadID() string {
	return m.thID
}

func (m *mockMsg) ThreadID() (string, error) {
	return m.thID, m.fail
}

func (m *mockMsg) Type() string {
	if m.msgType != "" {
		return m.msgType
	}

	if m.DIDCommMsgMap != nil {
		return m.DIDCommMsgMap.Type()
	}

	return ""
}
