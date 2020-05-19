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
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	serviceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/common/service"
	issuecredentialMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/protocol/issuecredential"
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/storage"
	verifiableStoreMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/store/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

const (
	Alice = "Alice"
	Bob   = "Bob"
)

func TestNew(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		storeProvider := storageMocks.NewMockProvider(ctrl)
		storeProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil).Times(1)

		verifiableStore := verifiableStoreMocks.NewMockStore(ctrl)

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore).AnyTimes()
		provider.EXPECT().VDRIRegistry().Return(nil)

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

// nolint: gocyclo
func TestService_HandleInbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const errMsg = "error"

	store := storageMocks.NewMockStore(ctrl)

	storeProvider := storageMocks.NewMockProvider(ctrl)
	storeProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil).AnyTimes()

	verifiableStore := verifiableStoreMocks.NewMockStore(ctrl)
	messenger := serviceMocks.NewMockMessenger(ctrl)

	provider := issuecredentialMocks.NewMockProvider(ctrl)
	provider.EXPECT().Messenger().Return(messenger).AnyTimes()
	provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()
	provider.EXPECT().VerifiableStore().Return(verifiableStore).AnyTimes()
	provider.EXPECT().VDRIRegistry().Return(nil).AnyTimes()

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

	t.Run("DB error (saveTransitionalPayload)", func(t *testing.T) {
		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(errors.New(errMsg))

		svc, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, svc.RegisterActionEvent(make(chan<- service.DIDCommAction)))

		msg := service.NewDIDCommMsgMap(ProposeCredential{
			Type: ProposeCredentialMsgType,
		})
		require.NoError(t, msg.SetID(uuid.New().String()))
		_, err = svc.HandleInbound(msg, "", "")
		require.Contains(t, fmt.Sprintf("%v", err), "save transitional payload: "+errMsg)
	})

	t.Run("Unrecognized msgType", func(t *testing.T) {
		svc, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, svc.RegisterActionEvent(make(chan<- service.DIDCommAction)))

		_, err = svc.HandleInbound(service.NewDIDCommMsgMap(struct{}{}), "", "")
		require.Contains(t, fmt.Sprintf("%v", err), "doHandle: nextState: unrecognized msgType: ")
	})

	t.Run("Receive Propose Credential Stop", func(t *testing.T) {
		var done = make(chan struct{})

		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_ string, msg service.DIDCommMsgMap, myDID, theirDID string) error {
				defer close(done)

				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Description.Code)
				require.Equal(t, ProblemReportMsgType, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(ProposeCredential{
			Type: ProposeCredentialMsgType,
		})

		require.NoError(t, msg.SetID(uuid.New().String()))

		_, err = svc.HandleInbound(msg, Alice, Bob)
		require.NoError(t, err)

		(<-ch).Stop(nil)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Propose Credential Continue", func(t *testing.T) {
		var done = make(chan struct{})

		messenger.EXPECT().ReplyTo(gomock.Any(), gomock.Any()).
			Do(func(_ string, msg service.DIDCommMsgMap) error {
				defer close(done)

				r := &OfferCredential{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, OfferCredentialMsgType, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "offer-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(ProposeCredential{
			Type: ProposeCredentialMsgType,
		})

		require.NoError(t, msg.SetID(uuid.New().String()))

		_, err = svc.HandleInbound(msg, Alice, Bob)
		require.NoError(t, err)

		(<-ch).Continue(WithOfferCredential(&OfferCredential{}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Propose Credential Continue (async)", func(t *testing.T) {
		var done = make(chan struct{})

		newProvider := issuecredentialMocks.NewMockProvider(ctrl)
		newProvider.EXPECT().Messenger().Return(messenger).AnyTimes()
		newProvider.EXPECT().StorageProvider().Return(mem.NewProvider()).AnyTimes()
		newProvider.EXPECT().VerifiableStore().Return(verifiableStore).AnyTimes()
		newProvider.EXPECT().VDRIRegistry().Return(nil)

		messenger.EXPECT().ReplyTo(gomock.Any(), gomock.Any()).
			Do(func(_ string, msg service.DIDCommMsgMap) error {
				defer close(done)

				r := &OfferCredential{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, OfferCredentialMsgType, r.Type)

				return nil
			})

		svc, err := New(newProvider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(ProposeCredential{
			Type: ProposeCredentialMsgType,
		})

		require.NoError(t, msg.SetID(uuid.New().String()))

		_, err = svc.HandleInbound(msg, Alice, Bob)
		require.NoError(t, err)

		actions, err := svc.Actions()
		require.NoError(t, err)
		for _, action := range actions {
			require.NoError(t, svc.ActionContinue(action.PIID, WithOfferCredential(&OfferCredential{})))
		}

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Propose Credential Stop (async)", func(t *testing.T) {
		var done = make(chan struct{})

		newProvider := issuecredentialMocks.NewMockProvider(ctrl)
		newProvider.EXPECT().Messenger().Return(messenger).AnyTimes()
		newProvider.EXPECT().StorageProvider().Return(mem.NewProvider()).AnyTimes()
		newProvider.EXPECT().VerifiableStore().Return(verifiableStore).AnyTimes()
		newProvider.EXPECT().VDRIRegistry().Return(nil)

		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_ string, msg service.DIDCommMsgMap, myDID, theirDID string) error {
				defer close(done)

				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Description.Code)
				require.Equal(t, ProblemReportMsgType, r.Type)

				return nil
			})

		svc, err := New(newProvider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(ProposeCredential{
			Type: ProposeCredentialMsgType,
		})

		require.NoError(t, msg.SetID(uuid.New().String()))

		_, err = svc.HandleInbound(msg, Alice, Bob)
		require.NoError(t, err)

		actions, err := svc.Actions()
		require.NoError(t, err)
		for _, action := range actions {
			require.NoError(t, svc.ActionStop(action.PIID, nil))
		}

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Offer Credential Stop", func(t *testing.T) {
		var done = make(chan struct{})

		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_ string, msg service.DIDCommMsgMap, myDID, theirDID string) error {
				defer close(done)

				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Description.Code)
				require.Equal(t, ProblemReportMsgType, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(OfferCredential{
			Type: OfferCredentialMsgType,
		})

		require.NoError(t, msg.SetID(uuid.New().String()))

		_, err = svc.HandleInbound(msg, Alice, Bob)
		require.NoError(t, err)

		(<-ch).Stop(nil)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Offer Credential Continue", func(t *testing.T) {
		var done = make(chan struct{})

		messenger.EXPECT().ReplyTo(gomock.Any(), gomock.Any()).
			Do(func(_ string, msg service.DIDCommMsgMap) error {
				defer close(done)

				r := &ProposeCredential{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, ProposeCredentialMsgType, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "proposal-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(OfferCredential{
			Type: OfferCredentialMsgType,
		})

		require.NoError(t, msg.SetID(uuid.New().String()))

		_, err = svc.HandleInbound(msg, Alice, Bob)
		require.NoError(t, err)

		(<-ch).Continue(WithProposeCredential(&ProposeCredential{}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Offer Credential", func(t *testing.T) {
		var done = make(chan struct{})
		var attachment = []decorator.Attachment{{ID: "ID1"}, {ID: "ID2"}}

		messenger.EXPECT().ReplyTo(gomock.Any(), gomock.Any()).
			Do(func(_ string, msg service.DIDCommMsgMap) error {
				defer close(done)

				r := &RequestCredential{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, RequestCredentialMsgType, r.Type)
				require.Equal(t, attachment, r.RequestsAttach)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "request-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(OfferCredential{
			Type:         OfferCredentialMsgType,
			OffersAttach: attachment,
		})

		require.NoError(t, msg.SetID(uuid.New().String()))

		_, err = svc.HandleInbound(msg, Alice, Bob)
		require.NoError(t, err)

		(<-ch).Continue(nil)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Request Credential Stop", func(t *testing.T) {
		var done = make(chan struct{})

		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_ string, msg service.DIDCommMsgMap, myDID, theirDID string) error {
				defer close(done)

				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Description.Code)
				require.Equal(t, ProblemReportMsgType, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(RequestCredential{
			Type: RequestCredentialMsgType,
		})

		require.NoError(t, msg.SetID(uuid.New().String()))

		_, err = svc.HandleInbound(msg, Alice, Bob)
		require.NoError(t, err)

		(<-ch).Stop(nil)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Request Credential Continue", func(t *testing.T) {
		var done = make(chan struct{})

		messenger.EXPECT().ReplyTo(gomock.Any(), gomock.Any()).
			Do(func(_ string, msg service.DIDCommMsgMap) error {
				defer close(done)

				r := &IssueCredential{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, IssueCredentialMsgType, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "credential-issued", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(RequestCredential{
			Type: RequestCredentialMsgType,
		})

		require.NoError(t, msg.SetID(uuid.New().String()))

		_, err = svc.HandleInbound(msg, Alice, Bob)
		require.NoError(t, err)

		(<-ch).Continue(WithIssueCredential(&IssueCredential{}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Issue Credential Continue", func(t *testing.T) {
		var done = make(chan struct{})

		messenger.EXPECT().ReplyTo(gomock.Any(), gomock.Any()).
			Do(func(_ string, msg service.DIDCommMsgMap) error {
				defer close(done)

				r := &model.Ack{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, AckMsgType, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return([]byte("request-sent"), nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		verifiableStore.EXPECT().SaveCredential(gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))
		var issued = time.Date(2010, time.January, 1, 19, 23, 24, 0, time.UTC)
		msg := service.NewDIDCommMsgMap(IssueCredential{
			Type: IssueCredentialMsgType,
			CredentialsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: &verifiable.Credential{
					Context: []string{
						"https://www.w3.org/2018/credentials/v1",
						"https://www.w3.org/2018/credentials/examples/v1"},
					ID: "http://example.edu/credentials/1872",
					Types: []string{
						"VerifiableCredential",
						"UniversityDegreeCredential"},
					Subject: struct {
						ID string
					}{ID: "SubjectID"},
					Issuer: verifiable.Issuer{
						ID:           "did:example:76e12ec712ebc6f1c221ebfeb1f",
						CustomFields: verifiable.CustomFields{"name": "Example University"},
					},
					Issued:  util.NewTime(issued),
					Schemas: []verifiable.TypedID{},
					CustomFields: map[string]interface{}{
						"referenceNumber": 83294847,
					},
				}}},
			},
		})

		require.NoError(t, msg.SetID(uuid.New().String()))

		_, err = svc.HandleInbound(msg, Alice, Bob)
		require.NoError(t, err)

		(<-ch).Continue(WithFriendlyNames("UniversityDegree"))

		select {
		case <-done:
			return
		case <-time.After(time.Second * 5):
			t.Error("timeout")
		}
	})

	t.Run("Receive Issue Credential Stop", func(t *testing.T) {
		var done = make(chan struct{})

		messenger.EXPECT().ReplyToNested(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_ string, msg service.DIDCommMsgMap, myDID, theirDID string) error {
				defer close(done)

				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Description.Code)
				require.Equal(t, ProblemReportMsgType, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return([]byte("request-sent"), nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(IssueCredential{
			Type: IssueCredentialMsgType,
		})

		require.NoError(t, msg.SetID(uuid.New().String()))

		_, err = svc.HandleInbound(msg, Alice, Bob)
		require.NoError(t, err)

		(<-ch).Stop(errors.New("invalid credential"))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Ack message", func(t *testing.T) {
		var done = make(chan struct{})

		store.EXPECT().Get(gomock.Any()).Return([]byte("credential-issued"), nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			defer close(done)

			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, svc.RegisterActionEvent(make(chan service.DIDCommAction)))

		msg := service.NewDIDCommMsgMap(model.Ack{
			Type: AckMsgType,
		})

		require.NoError(t, msg.SetID(uuid.New().String()))

		_, err = svc.HandleInbound(msg, Alice, Bob)
		require.NoError(t, err)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
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
	storeProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil).AnyTimes()

	verifiableStore := verifiableStoreMocks.NewMockStore(ctrl)
	messenger := serviceMocks.NewMockMessenger(ctrl)

	provider := issuecredentialMocks.NewMockProvider(ctrl)
	provider.EXPECT().Messenger().Return(messenger).AnyTimes()
	provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()
	provider.EXPECT().VerifiableStore().Return(verifiableStore).AnyTimes()
	provider.EXPECT().VDRIRegistry().Return(nil).AnyTimes()

	t.Run("DB error", func(t *testing.T) {
		store.EXPECT().Get(gomock.Any()).Return(nil, errors.New(errMsg))

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(struct{}{})
		require.NoError(t, msg.SetID(uuid.New().String()))

		err = svc.HandleOutbound(msg, "", "")
		require.Contains(t, fmt.Sprintf("%v", err), "doHandle: getCurrentStateNameAndPIID: currentStateName: "+errMsg)
	})

	t.Run("Unrecognized msgType", func(t *testing.T) {
		svc, err := New(provider)
		require.NoError(t, err)

		err = svc.HandleOutbound(service.NewDIDCommMsgMap(ProposeCredential{
			Type: "none",
		}), "", "")
		require.Contains(t, fmt.Sprintf("%v", err), "doHandle: nextState: unrecognized msgType: none")
	})

	t.Run("Send Propose Credential", func(t *testing.T) {
		var done = make(chan struct{})

		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "proposal-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(ProposeCredential{
			Type: ProposeCredentialMsgType,
		})

		messenger.EXPECT().Send(msg, Alice, Bob).
			Do(func(msg service.DIDCommMsgMap, myDID, theirDID string) error {
				defer close(done)

				return nil
			})

		err = svc.HandleOutbound(msg, Alice, Bob)
		require.NoError(t, err)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Send Propose Credential with error", func(t *testing.T) {
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(ProposeCredential{
			Type: ProposeCredentialMsgType,
		})

		messenger.EXPECT().Send(msg, Alice, Bob).Return(errors.New(errMsg))

		err = svc.HandleOutbound(msg, Alice, Bob)
		require.Contains(t, fmt.Sprintf("%v", err), "action proposal-sent: "+errMsg)
	})

	t.Run("Send Offer Credential", func(t *testing.T) {
		var done = make(chan struct{})

		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "offer-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(OfferCredential{
			Type: OfferCredentialMsgType,
		})

		messenger.EXPECT().Send(msg, Alice, Bob).
			Do(func(msg service.DIDCommMsgMap, myDID, theirDID string) error {
				defer close(done)

				return nil
			})

		err = svc.HandleOutbound(msg, Alice, Bob)
		require.NoError(t, err)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Send Offer with error", func(t *testing.T) {
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(OfferCredential{
			Type: OfferCredentialMsgType,
		})

		messenger.EXPECT().Send(msg, Alice, Bob).Return(errors.New(errMsg))

		err = svc.HandleOutbound(msg, Alice, Bob)
		require.Contains(t, fmt.Sprintf("%v", err), "action offer-sent: "+errMsg)
	})

	t.Run("Send Request Credential", func(t *testing.T) {
		var done = make(chan struct{})

		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "request-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(RequestCredential{
			Type: RequestCredentialMsgType,
		})

		messenger.EXPECT().Send(msg, Alice, Bob).
			Do(func(msg service.DIDCommMsgMap, myDID, theirDID string) error {
				defer close(done)

				return nil
			})

		err = svc.HandleOutbound(msg, Alice, Bob)
		require.NoError(t, err)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Send Request with error", func(t *testing.T) {
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(RequestCredential{
			Type: RequestCredentialMsgType,
		})

		messenger.EXPECT().Send(msg, Alice, Bob).Return(errors.New(errMsg))

		err = svc.HandleOutbound(msg, Alice, Bob)
		require.Contains(t, fmt.Sprintf("%v", err), "action request-sent: "+errMsg)
	})
}

func TestService_ActionContinue(t *testing.T) {
	t.Run("Error transitional payload (get)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		const errMsg = "error"

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).Return(nil, errors.New(errMsg))

		storeProvider := storageMocks.NewMockProvider(ctrl)
		storeProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil).AnyTimes()

		verifiableStore := verifiableStoreMocks.NewMockStore(ctrl)
		messenger := serviceMocks.NewMockMessenger(ctrl)

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(messenger)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore).AnyTimes()
		provider.EXPECT().VDRIRegistry().Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		err = svc.ActionContinue("piID", nil)
		require.Contains(t, fmt.Sprintf("%v", err), "get transitional payload: store get: "+errMsg)
	})

	t.Run("Error transitional payload (delete)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		const errMsg = "error"

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).Return([]byte(`{}`), nil)
		store.EXPECT().Delete(gomock.Any()).Return(errors.New(errMsg))

		storeProvider := storageMocks.NewMockProvider(ctrl)
		storeProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil).AnyTimes()

		verifiableStore := verifiableStoreMocks.NewMockStore(ctrl)
		messenger := serviceMocks.NewMockMessenger(ctrl)

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(messenger)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore).AnyTimes()
		provider.EXPECT().VDRIRegistry().Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		err = svc.ActionContinue("piID", nil)
		require.Contains(t, fmt.Sprintf("%v", err), "delete transitional payload: "+errMsg)
	})
}

func TestService_ActionStop(t *testing.T) {
	t.Run("Error transitional payload (get)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		const errMsg = "error"

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).Return(nil, errors.New(errMsg))

		storeProvider := storageMocks.NewMockProvider(ctrl)
		storeProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil).AnyTimes()

		verifiableStore := verifiableStoreMocks.NewMockStore(ctrl)
		messenger := serviceMocks.NewMockMessenger(ctrl)

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(messenger)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore).AnyTimes()
		provider.EXPECT().VDRIRegistry().Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		err = svc.ActionStop("piID", nil)
		require.Contains(t, fmt.Sprintf("%v", err), "get transitional payload: store get: "+errMsg)
	})

	t.Run("Error transitional payload (delete)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		const errMsg = "error"

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).Return([]byte(`{}`), nil)
		store.EXPECT().Delete(gomock.Any()).Return(errors.New(errMsg))

		storeProvider := storageMocks.NewMockProvider(ctrl)
		storeProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil).AnyTimes()

		verifiableStore := verifiableStoreMocks.NewMockStore(ctrl)
		messenger := serviceMocks.NewMockMessenger(ctrl)

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(messenger)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore).AnyTimes()
		provider.EXPECT().VDRIRegistry().Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		err = svc.ActionStop("piID", nil)
		require.Contains(t, fmt.Sprintf("%v", err), "delete transitional payload: "+errMsg)
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

	require.True(t, canTriggerActionEvents(service.NewDIDCommMsgMap(IssueCredential{
		Type: IssueCredentialMsgType,
	})))

	require.True(t, canTriggerActionEvents(service.NewDIDCommMsgMap(RequestCredential{
		Type: RequestCredentialMsgType,
	})))

	require.False(t, canTriggerActionEvents(service.NewDIDCommMsgMap(struct{}{})))
}
