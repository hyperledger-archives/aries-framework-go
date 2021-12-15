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

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	serviceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/common/service"
	issuecredentialMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/protocol/issuecredential"
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/spi/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	Alice = "Alice"
	Bob   = "Bob"
)

func TestService_UseV2(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success (one function)", func(t *testing.T) {
		storeProvider := mem.NewProvider()

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

		svc, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, svc)

		meta := &MetaData{
			state: &done{},
			msgClone: service.NewDIDCommMsgMap(struct {
				Type string `json:"@type"`
			}{
				Type: IssueCredentialMsgTypeV2,
			}),
			offerCredentialV2:   &OfferCredentialV2{Type: OfferCredentialMsgTypeV2},
			proposeCredentialV2: &ProposeCredentialV2{Type: ProposeCredentialMsgTypeV2},
			issueCredentialV2:   &IssueCredentialV2{Type: IssueCredentialMsgTypeV2},
			requestCredentialV2: &RequestCredentialV2{Type: RequestCredentialMsgTypeV2},
			credentialNames:     []string{"name"},
		}
		var executed bool
		svc.Use(func(next Handler) Handler {
			return HandlerFunc(func(metadata Metadata) error {
				require.Equal(t, meta.msgClone, metadata.Message())
				require.Equal(t, metadata.Message().Type(), IssueCredentialMsgTypeV2)
				require.Equal(t, meta.offerCredentialV2, metadata.OfferCredentialV2())
				require.Equal(t, meta.proposeCredentialV2, metadata.ProposeCredentialV2())
				require.Equal(t, meta.issueCredentialV2, metadata.IssueCredentialV2())
				require.Equal(t, meta.requestCredentialV2, metadata.RequestCredentialV2())
				require.Equal(t, meta.credentialNames, metadata.CredentialNames())
				require.Equal(t, meta.state.Name(), metadata.StateName())

				executed = true
				return next.Handle(metadata)
			})
		})

		_, _, err = svc.execute(meta.state, meta)
		require.EqualError(t, err, "done: ExecuteOutbound is not implemented yet")

		require.True(t, executed)
	})

	t.Run("Success (two function)", func(t *testing.T) {
		storeProvider := mem.NewProvider()

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

		svc, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, svc)

		var executed bool
		svc.Use(func(next Handler) Handler {
			return HandlerFunc(func(metadata Metadata) error {
				executed = true
				return next.Handle(metadata)
			})
		}, func(next Handler) Handler {
			return HandlerFunc(func(metadata Metadata) error {
				require.True(t, executed)
				return next.Handle(metadata)
			})
		})

		_, _, err = svc.execute(&done{}, &MetaData{})
		require.EqualError(t, err, "done: ExecuteOutbound is not implemented yet")
	})

	t.Run("Failed", func(t *testing.T) {
		storeProvider := mem.NewProvider()

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

		svc, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, svc)

		const msgErr = "error message"
		svc.Use(func(next Handler) Handler {
			return HandlerFunc(func(metadata Metadata) error {
				return errors.New(msgErr)
			})
		})

		_, _, err = svc.execute(&done{}, &MetaData{})
		require.EqualError(t, err, "middleware: "+msgErr)
	})
}

func TestService_UseV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success (one function)", func(t *testing.T) {
		storeProvider := mem.NewProvider()

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

		svc, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, svc)

		meta := &MetaData{
			state: &done{},
			msgClone: service.NewDIDCommMsgMap(struct {
				Type string `json:"@type"`
			}{
				Type: IssueCredentialMsgTypeV3,
			}),
			offerCredentialV2:   &OfferCredentialV2{Type: OfferCredentialMsgTypeV3},
			proposeCredentialV2: &ProposeCredentialV2{Type: ProposeCredentialMsgTypeV3},
			issueCredentialV2:   &IssueCredentialV2{Type: IssueCredentialMsgTypeV3},
			requestCredentialV2: &RequestCredentialV2{Type: RequestCredentialMsgTypeV3},
			credentialNames:     []string{"name"},
		}
		var executed bool
		svc.Use(func(next Handler) Handler {
			return HandlerFunc(func(metadata Metadata) error {
				require.Equal(t, meta.msgClone, metadata.Message())
				require.Equal(t, metadata.Message().Type(), IssueCredentialMsgTypeV3)
				require.Equal(t, meta.offerCredentialV2, metadata.OfferCredentialV2())
				require.Equal(t, meta.proposeCredentialV2, metadata.ProposeCredentialV2())
				require.Equal(t, meta.issueCredentialV2, metadata.IssueCredentialV2())
				require.Equal(t, meta.requestCredentialV2, metadata.RequestCredentialV2())
				require.Equal(t, meta.credentialNames, metadata.CredentialNames())
				require.Equal(t, meta.state.Name(), metadata.StateName())

				executed = true
				return next.Handle(metadata)
			})
		})

		_, _, err = svc.execute(meta.state, meta)
		require.EqualError(t, err, "done: ExecuteOutbound is not implemented yet")

		require.True(t, executed)
	})
}

func TestNew(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		storeProvider := mem.NewProvider()

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

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

func TestService_Initialize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success", func(t *testing.T) {
		storeProvider := mem.NewProvider()

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

		svc := Service{}

		err := svc.Initialize(provider)
		require.NoError(t, err)

		// second init is no-op
		err = svc.Initialize(provider)
		require.NoError(t, err)
	})

	t.Run("failure, not given a valid provider", func(t *testing.T) {
		svc := Service{}

		err := svc.Initialize("not a provider")
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected provider of type")
	})
}

// nolint: gocyclo,gocognit
func TestService_HandleInboundV2(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const errMsg = "error"

	store := storageMocks.NewMockStore(ctrl)

	storeProvider := storageMocks.NewMockProvider(ctrl)
	storeProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil).AnyTimes()
	storeProvider.EXPECT().SetStoreConfig(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	messenger := serviceMocks.NewMockMessenger(ctrl)

	provider := issuecredentialMocks.NewMockProvider(ctrl)
	provider.EXPECT().Messenger().Return(messenger).AnyTimes()
	provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

	t.Run("No clients", func(t *testing.T) {
		svc, err := New(provider)
		require.NoError(t, err)

		_, err = svc.HandleInbound(nil, service.EmptyDIDCommContext())
		require.Contains(t, fmt.Sprintf("%v", err), "no clients")
	})

	t.Run("DB error", func(t *testing.T) {
		store.EXPECT().Get(gomock.Any()).Return(nil, errors.New(errMsg))

		svc, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, svc.RegisterActionEvent(make(chan<- service.DIDCommAction)))

		msg := service.NewDIDCommMsgMap(struct{}{})
		msg.SetID(uuid.New().String())
		_, err = svc.HandleInbound(msg, service.EmptyDIDCommContext())
		require.Contains(t, fmt.Sprintf("%v", err), "doHandle: getCurrentStateNameAndPIID: currentStateName: "+errMsg)
	})

	t.Run("DB error (saveTransitionalPayload)", func(t *testing.T) {
		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New(errMsg))

		svc, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, svc.RegisterActionEvent(make(chan<- service.DIDCommAction)))

		msg := service.NewDIDCommMsgMap(ProposeCredentialV2{
			Type: ProposeCredentialMsgTypeV2,
		})
		msg.SetID(uuid.New().String())
		_, err = svc.HandleInbound(msg, service.EmptyDIDCommContext())
		require.Contains(t, fmt.Sprintf("%v", err), "save transitional payload: "+errMsg)
	})

	t.Run("Unrecognized msgType", func(t *testing.T) {
		svc, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, svc.RegisterActionEvent(make(chan<- service.DIDCommAction)))

		_, err = svc.HandleInbound(service.NewDIDCommMsgMap(struct{}{}), service.EmptyDIDCommContext())
		require.Contains(t, fmt.Sprintf("%v", err), "doHandle: nextState: unrecognized msgType: ")
	})

	t.Run("Receive Propose Credential Stop", func(t *testing.T) {
		done := make(chan struct{})

		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
				defer close(done)

				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Description.Code)
				require.Equal(t, ProblemReportMsgTypeV2, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(ProposeCredentialV2{
			Type: ProposeCredentialMsgTypeV2,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)
		require.Equal(t, properties.All()["myDID"], Alice)
		require.Equal(t, properties.All()["theirDID"], Bob)

		action.Stop(nil)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Propose Credential Continue", func(t *testing.T) {
		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &OfferCredentialV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, OfferCredentialMsgTypeV2, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "offer-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(ProposeCredentialV2{
			Type: ProposeCredentialMsgTypeV2,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithOfferCredential(&OfferCredentialParams{}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Propose Credential Continue (async)", func(t *testing.T) {
		done := make(chan struct{})

		newProvider := issuecredentialMocks.NewMockProvider(ctrl)
		newProvider.EXPECT().Messenger().Return(messenger).AnyTimes()
		newProvider.EXPECT().StorageProvider().Return(mem.NewProvider()).AnyTimes()

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &OfferCredentialV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, OfferCredentialMsgTypeV2, r.Type)

				return nil
			})

		svc, err := New(newProvider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(ProposeCredentialV2{
			Type: ProposeCredentialMsgTypeV2,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		actions, err := svc.Actions()
		require.NoError(t, err)
		for _, action := range actions {
			require.Equal(t, action.MyDID, Alice)
			require.Equal(t, action.TheirDID, Bob)
			require.NoError(t, svc.ActionContinue(action.PIID, WithOfferCredential(&OfferCredentialParams{})))
		}

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Propose Credential Stop (async)", func(t *testing.T) {
		done := make(chan struct{})

		newProvider := issuecredentialMocks.NewMockProvider(ctrl)
		newProvider.EXPECT().Messenger().Return(messenger).AnyTimes()
		newProvider.EXPECT().StorageProvider().Return(mem.NewProvider()).AnyTimes()

		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
				defer close(done)

				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Description.Code)
				require.Equal(t, ProblemReportMsgTypeV2, r.Type)

				return nil
			})

		svc, err := New(newProvider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(ProposeCredentialV2{
			Type: ProposeCredentialMsgTypeV2,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		actions, err := svc.Actions()
		require.NoError(t, err)
		for _, action := range actions {
			require.Equal(t, action.MyDID, Alice)
			require.Equal(t, action.TheirDID, Bob)
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
		done := make(chan struct{})

		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
				defer close(done)

				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Description.Code)
				require.Equal(t, ProblemReportMsgTypeV2, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(OfferCredentialV2{
			Type: OfferCredentialMsgTypeV2,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Stop(nil)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Offer Credential Continue with Proposal", func(t *testing.T) {
		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &ProposeCredentialV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, ProposeCredentialMsgTypeV2, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "proposal-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(OfferCredentialV2{
			Type: OfferCredentialMsgTypeV2,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithProposeCredential(&ProposeCredentialParams{}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Offer Credential Continue with Invitation", func(t *testing.T) {
		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &RequestCredentialV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, RequestCredentialMsgTypeV2, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "request-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(OfferCredentialV2{
			Type: OfferCredentialMsgTypeV2,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithRequestCredential(&RequestCredentialParams{Comment: "test"}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Offer Credential", func(t *testing.T) {
		done := make(chan struct{})
		attachment := []decorator.Attachment{{ID: "ID1"}, {ID: "ID2"}}

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &RequestCredentialV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, RequestCredentialMsgTypeV2, r.Type)
				require.Equal(t, attachment, r.RequestsAttach)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "request-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(OfferCredentialV2{
			Type:         OfferCredentialMsgTypeV2,
			OffersAttach: attachment,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(nil)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Invitation Credential Stop", func(t *testing.T) {
		done := make(chan struct{})

		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
				defer close(done)

				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Description.Code)
				require.Equal(t, ProblemReportMsgTypeV2, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(RequestCredentialV2{
			Type: RequestCredentialMsgTypeV2,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Stop(nil)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Invitation Credential Continue", func(t *testing.T) {
		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &IssueCredentialV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, IssueCredentialMsgTypeV2, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "credential-issued", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(RequestCredentialV2{
			Type: RequestCredentialMsgTypeV2,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithIssueCredential(&IssueCredentialParams{}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Problem Report (continue)", func(t *testing.T) {
		done := make(chan struct{})

		store.EXPECT().Get(gomock.Any()).Return([]byte("request-sent"), nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			defer close(done)

			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(RequestCredentialV2{
			Type: ProblemReportMsgTypeV2,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithIssueCredential(&IssueCredentialParams{}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Problem Report (stop)", func(t *testing.T) {
		done := make(chan struct{})

		store.EXPECT().Get(gomock.Any()).Return([]byte("request-sent"), nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			defer close(done)

			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(RequestCredentialV2{
			Type: ProblemReportMsgTypeV2,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Stop(nil)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Issue Credential Continue", func(t *testing.T) {
		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &model.Ack{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, AckMsgTypeV2, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return([]byte("request-sent"), nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))
		issued := time.Date(2010, time.January, 1, 19, 23, 24, 0, time.UTC)
		msg := service.NewDIDCommMsgMap(IssueCredentialV2{
			Type: IssueCredentialMsgTypeV2,
			CredentialsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: &verifiable.Credential{
					Context: []string{
						"https://www.w3.org/2018/credentials/v1",
						"https://www.w3.org/2018/credentials/examples/v1",
					},
					ID: "http://example.edu/credentials/1872",
					Types: []string{
						"VerifiableCredential",
						"UniversityDegreeCredential",
					},
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

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithFriendlyNames("UniversityDegree"))

		select {
		case <-done:
			return
		case <-time.After(time.Second * 5):
			t.Error("timeout")
		}
	})

	t.Run("Receive Issue Credential Stop", func(t *testing.T) {
		done := make(chan struct{})

		messenger.EXPECT().ReplyToNested(gomock.Any(), gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
				defer close(done)

				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Description.Code)
				require.Equal(t, ProblemReportMsgTypeV2, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return([]byte("request-sent"), nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(IssueCredentialV2{
			Type: IssueCredentialMsgTypeV2,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Stop(errors.New("invalid credential"))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Ack message", func(t *testing.T) {
		done := make(chan struct{})

		store.EXPECT().Get(gomock.Any()).Return([]byte("credential-issued"), nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			defer close(done)

			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, svc.RegisterActionEvent(make(chan service.DIDCommAction)))

		msg := service.NewDIDCommMsgMap(model.Ack{
			Type: AckMsgTypeV2,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
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
			Type: ProblemReportMsgTypeV2,
		}), service.EmptyDIDCommContext())
		require.Contains(t, fmt.Sprintf("%v", err), "doHandle: invalid state transition")
	})
}

// nolint: gocyclo,gocognit
func TestService_HandleInboundV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const errMsg = "error"

	initMocks := func(controller *gomock.Controller) (
		store *storageMocks.MockStore,
		messenger *serviceMocks.MockMessenger,
		provider *issuecredentialMocks.MockProvider,
	) {
		store = storageMocks.NewMockStore(controller)

		storeProvider := storageMocks.NewMockProvider(controller)
		storeProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil).AnyTimes()
		storeProvider.EXPECT().SetStoreConfig(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		messenger = serviceMocks.NewMockMessenger(controller)

		provider = issuecredentialMocks.NewMockProvider(controller)
		provider.EXPECT().Messenger().Return(messenger).AnyTimes()
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

		return store, messenger, provider
	}

	t.Run("DB error (saveTransitionalPayload)", func(t *testing.T) {
		store, _, provider := initMocks(ctrl)

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New(errMsg))

		svc, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, svc.RegisterActionEvent(make(chan<- service.DIDCommAction)))

		msg := service.NewDIDCommMsgMap(ProposeCredentialV2{
			Type: ProposeCredentialMsgTypeV3,
		})
		msg.SetID(uuid.New().String())
		_, err = svc.HandleInbound(msg, service.EmptyDIDCommContext())
		require.Contains(t, fmt.Sprintf("%v", err), "save transitional payload: "+errMsg)
	})

	t.Run("Receive Propose Credential Stop", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
				defer close(done)

				r := &model.ProblemReportV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Body.Code)
				require.Equal(t, ProblemReportMsgTypeV3, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(ProposeCredentialV2{
			Type: ProposeCredentialMsgTypeV3,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)
		require.Equal(t, properties.All()["myDID"], Alice)
		require.Equal(t, properties.All()["theirDID"], Bob)

		action.Stop(nil)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Propose Credential Continue", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &OfferCredentialV3{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, OfferCredentialMsgTypeV3, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "offer-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(ProposeCredentialV3{
			Type: ProposeCredentialMsgTypeV3,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithOfferCredential(&OfferCredentialParams{}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Propose Credential Continue (async)", func(t *testing.T) {
		_, messenger, _ := initMocks(ctrl)

		done := make(chan struct{})

		newProvider := issuecredentialMocks.NewMockProvider(ctrl)
		newProvider.EXPECT().Messenger().Return(messenger).AnyTimes()
		newProvider.EXPECT().StorageProvider().Return(mem.NewProvider()).AnyTimes()

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &OfferCredentialV3{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, OfferCredentialMsgTypeV3, r.Type)

				return nil
			})

		svc, err := New(newProvider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(ProposeCredentialV3{
			Type: ProposeCredentialMsgTypeV3,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		actions, err := svc.Actions()
		require.NoError(t, err)
		for _, action := range actions {
			require.Equal(t, action.MyDID, Alice)
			require.Equal(t, action.TheirDID, Bob)
			require.NoError(t, svc.ActionContinue(action.PIID, WithOfferCredential(&OfferCredentialParams{})))
		}

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Propose Credential Stop (async)", func(t *testing.T) {
		_, messenger, _ := initMocks(ctrl)

		done := make(chan struct{})

		newProvider := issuecredentialMocks.NewMockProvider(ctrl)
		newProvider.EXPECT().Messenger().Return(messenger).AnyTimes()
		newProvider.EXPECT().StorageProvider().Return(mem.NewProvider()).AnyTimes()

		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
				defer close(done)

				r := &model.ProblemReportV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Body.Code)
				require.Equal(t, ProblemReportMsgTypeV3, r.Type)

				return nil
			})

		svc, err := New(newProvider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(ProposeCredentialV3{
			Type: ProposeCredentialMsgTypeV3,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		actions, err := svc.Actions()
		require.NoError(t, err)
		for _, action := range actions {
			require.Equal(t, action.MyDID, Alice)
			require.Equal(t, action.TheirDID, Bob)
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
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
				defer close(done)

				r := &model.ProblemReportV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Body.Code)
				require.Equal(t, ProblemReportMsgTypeV3, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(OfferCredentialV3{
			Type: OfferCredentialMsgTypeV3,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Stop(nil)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Offer Credential Continue with Proposal", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &ProposeCredentialV3{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, ProposeCredentialMsgTypeV3, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "proposal-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(OfferCredentialV3{
			Type: OfferCredentialMsgTypeV3,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithProposeCredential(&ProposeCredentialParams{}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Offer Credential Continue with Invitation", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &RequestCredentialV3{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, RequestCredentialMsgTypeV3, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "request-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(OfferCredentialV3{
			Type: OfferCredentialMsgTypeV3,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithRequestCredential(&RequestCredentialParams{Comment: "test"}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Offer Credential", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})
		attachment := []decorator.AttachmentV2{{ID: "ID1"}, {ID: "ID2"}}

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &RequestCredentialV3{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, RequestCredentialMsgTypeV3, r.Type)
				require.Equal(t, attachment, r.Attachments)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "request-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(OfferCredentialV3{
			Type:        OfferCredentialMsgTypeV3,
			Attachments: attachment,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(nil)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Invitation Credential Stop", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
				defer close(done)

				r := &model.ProblemReportV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Body.Code)
				require.Equal(t, ProblemReportMsgTypeV3, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(RequestCredentialV3{
			Type: RequestCredentialMsgTypeV3,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Stop(nil)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Invitation Credential Continue", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &IssueCredentialV3{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, IssueCredentialMsgTypeV3, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "credential-issued", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(RequestCredentialV3{
			Type: RequestCredentialMsgTypeV3,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithIssueCredential(&IssueCredentialParams{}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Problem Report (continue)", func(t *testing.T) {
		store, _, provider := initMocks(ctrl)

		done := make(chan struct{})

		store.EXPECT().Get(gomock.Any()).Return([]byte("request-sent"), nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			defer close(done)

			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(RequestCredentialV3{
			Type: ProblemReportMsgTypeV3,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithIssueCredential(&IssueCredentialParams{}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Problem Report (stop)", func(t *testing.T) {
		store, _, provider := initMocks(ctrl)

		done := make(chan struct{})

		store.EXPECT().Get(gomock.Any()).Return([]byte("request-sent"), nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			defer close(done)

			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(RequestCredentialV3{
			Type: ProblemReportMsgTypeV3,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Stop(nil)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Issue Credential Continue", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &model.AckV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, AckMsgTypeV3, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return([]byte("request-sent"), nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))
		issued := time.Date(2010, time.January, 1, 19, 23, 24, 0, time.UTC)
		msg := service.NewDIDCommMsgMap(IssueCredentialV3{
			Type: IssueCredentialMsgTypeV3,
			Attachments: []decorator.AttachmentV2{
				{Data: decorator.AttachmentData{JSON: &verifiable.Credential{
					Context: []string{
						"https://www.w3.org/2018/credentials/v1",
						"https://www.w3.org/2018/credentials/examples/v1",
					},
					ID: "http://example.edu/credentials/1872",
					Types: []string{
						"VerifiableCredential",
						"UniversityDegreeCredential",
					},
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

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithFriendlyNames("UniversityDegree"))

		select {
		case <-done:
			return
		case <-time.After(time.Second * 5):
			t.Error("timeout")
		}
	})

	t.Run("Receive Issue Credential Stop", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().ReplyToNested(gomock.Any(), gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
				defer close(done)

				r := &model.ProblemReportV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeRejectedError, r.Body.Code)
				require.Equal(t, ProblemReportMsgTypeV3, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return([]byte("request-sent"), nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(IssueCredentialV3{
			Type: IssueCredentialMsgTypeV3,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Stop(errors.New("invalid credential"))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Ack message", func(t *testing.T) {
		store, _, provider := initMocks(ctrl)

		done := make(chan struct{})

		store.EXPECT().Get(gomock.Any()).Return([]byte("credential-issued"), nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			defer close(done)

			require.Equal(t, "done", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, svc.RegisterActionEvent(make(chan service.DIDCommAction)))

		msg := service.NewDIDCommMsgMap(model.AckV2{
			Type: AckMsgTypeV3,
		})

		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Invalid state transition", func(t *testing.T) {
		store, _, provider := initMocks(ctrl)
		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		chState := make(chan service.StateMsg, 2)
		require.NoError(t, svc.RegisterMsgEvent(chState))

		_, err = svc.HandleInbound(service.NewDIDCommMsgMap(model.ProblemReportV2{
			Type: ProblemReportMsgTypeV3,
		}), service.EmptyDIDCommContext())
		require.Contains(t, fmt.Sprintf("%v", err), "doHandle: invalid state transition")
	})
}

func TestService_HandleOutbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const errMsg = "error"

	initMocks := func(controller *gomock.Controller) (
		store *storageMocks.MockStore,
		messenger *serviceMocks.MockMessenger,
		provider *issuecredentialMocks.MockProvider,
	) {
		store = storageMocks.NewMockStore(controller)

		storeProvider := storageMocks.NewMockProvider(controller)
		storeProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil).AnyTimes()
		storeProvider.EXPECT().SetStoreConfig(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		messenger = serviceMocks.NewMockMessenger(controller)

		provider = issuecredentialMocks.NewMockProvider(controller)
		provider.EXPECT().Messenger().Return(messenger).AnyTimes()
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

		return store, messenger, provider
	}

	t.Run("DB error", func(t *testing.T) {
		store, _, provider := initMocks(ctrl)

		store.EXPECT().Get(gomock.Any()).Return(nil, errors.New(errMsg))

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(struct{}{})
		msg.SetID(uuid.New().String())

		piid, err := svc.HandleOutbound(msg, "", "")
		require.Empty(t, piid)
		require.Contains(t, fmt.Sprintf("%v", err), "doHandle: getCurrentStateNameAndPIID: currentStateName: "+errMsg)
	})

	t.Run("Unrecognized msgType", func(t *testing.T) {
		store, _, provider := initMocks(ctrl)

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()

		svc, err := New(provider)
		require.NoError(t, err)

		piid, err := svc.HandleOutbound(service.NewDIDCommMsgMap(ProposeCredentialV2{
			Type: "none",
		}), "", "")
		require.Empty(t, piid)
		require.Contains(t, fmt.Sprintf("%v", err), "doHandle: nextState: unrecognized msgType: none")
	})

	t.Run("Send Propose Credential", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "proposal-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(ProposeCredentialV2{
			Type: ProposeCredentialMsgTypeV2,
		})

		messenger.EXPECT().Send(msg, Alice, Bob, gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, myDID, theirDID string, opts ...service.Opt) error {
				defer close(done)

				return nil
			})

		piid, err := svc.HandleOutbound(msg, Alice, Bob)
		require.NoError(t, err)
		require.NotEmpty(t, piid)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Send Propose Credential with error", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(ProposeCredentialV2{
			Type: ProposeCredentialMsgTypeV2,
		})

		messenger.EXPECT().Send(msg, Alice, Bob, gomock.Any()).Return(errors.New(errMsg))

		piid, err := svc.HandleOutbound(msg, Alice, Bob)
		require.Empty(t, piid)
		require.Contains(t, fmt.Sprintf("%v", err), "action proposal-sent: "+errMsg)
	})

	t.Run("Send Offer Credential", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "offer-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(OfferCredentialV2{
			Type: OfferCredentialMsgTypeV2,
		})

		messenger.EXPECT().Send(msg, Alice, Bob, gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, myDID, theirDID string, opts ...service.Opt) error {
				defer close(done)

				return nil
			})

		piid, err := svc.HandleOutbound(msg, Alice, Bob)
		require.NotEmpty(t, piid)
		require.NoError(t, err)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Send Offer with error", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(OfferCredentialV2{
			Type: OfferCredentialMsgTypeV2,
		})

		messenger.EXPECT().Send(msg, Alice, Bob, gomock.Any()).Return(errors.New(errMsg))

		piid, err := svc.HandleOutbound(msg, Alice, Bob)
		require.Empty(t, piid)
		require.Contains(t, fmt.Sprintf("%v", err), "action offer-sent: "+errMsg)
	})

	t.Run("Send Invitation Credential", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "request-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(RequestCredentialV2{
			Type: RequestCredentialMsgTypeV2,
		})

		messenger.EXPECT().Send(msg, Alice, Bob, gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, myDID, theirDID string, opts ...service.Opt) error {
				defer close(done)

				return nil
			})

		piid, err := svc.HandleOutbound(msg, Alice, Bob)
		require.NotEmpty(t, piid)
		require.NoError(t, err)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Send Invitation with error", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(RequestCredentialV2{
			Type: RequestCredentialMsgTypeV2,
		})

		messenger.EXPECT().Send(msg, Alice, Bob, gomock.Any()).Return(errors.New(errMsg))

		piid, err := svc.HandleOutbound(msg, Alice, Bob)
		require.Empty(t, piid)
		require.Contains(t, fmt.Sprintf("%v", err), "action request-sent: "+errMsg)
	})
}

func TestService_HandleOutboundV3(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const errMsg = "error"

	initMocks := func(controller *gomock.Controller) (
		store *storageMocks.MockStore,
		messenger *serviceMocks.MockMessenger,
		provider *issuecredentialMocks.MockProvider,
	) {
		store = storageMocks.NewMockStore(controller)
		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()

		storeProvider := storageMocks.NewMockProvider(controller)
		storeProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil).AnyTimes()
		storeProvider.EXPECT().SetStoreConfig(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		messenger = serviceMocks.NewMockMessenger(controller)

		provider = issuecredentialMocks.NewMockProvider(controller)
		provider.EXPECT().Messenger().Return(messenger).AnyTimes()
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

		return store, messenger, provider
	}

	t.Run("Send Propose Credential", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "proposal-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(ProposeCredentialV3{
			Type: ProposeCredentialMsgTypeV3,
		})

		messenger.EXPECT().Send(msg, Alice, Bob, gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, myDID, theirDID string, opts ...service.Opt) error {
				defer close(done)

				return nil
			})

		piid, err := svc.HandleOutbound(msg, Alice, Bob)
		require.NotEmpty(t, piid)
		require.NoError(t, err)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Send Propose Credential with error", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(ProposeCredentialV3{
			Type: ProposeCredentialMsgTypeV3,
		})

		messenger.EXPECT().Send(msg, Alice, Bob, gomock.Any()).Return(errors.New(errMsg))

		piid, err := svc.HandleOutbound(msg, Alice, Bob)
		require.Empty(t, piid)
		require.Contains(t, fmt.Sprintf("%v", err), "action proposal-sent: "+errMsg)
	})

	t.Run("Send Offer Credential", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "offer-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(OfferCredentialV3{
			Type: OfferCredentialMsgTypeV3,
		})

		messenger.EXPECT().Send(msg, Alice, Bob, gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, myDID, theirDID string, opts ...service.Opt) error {
				defer close(done)

				return nil
			})

		piid, err := svc.HandleOutbound(msg, Alice, Bob)
		require.NotEmpty(t, piid)
		require.NoError(t, err)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Send Offer with error", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(OfferCredentialV3{
			Type: OfferCredentialMsgTypeV3,
		})

		messenger.EXPECT().Send(msg, Alice, Bob, gomock.Any()).Return(errors.New(errMsg))

		piid, err := svc.HandleOutbound(msg, Alice, Bob)
		require.Empty(t, piid)
		require.Contains(t, fmt.Sprintf("%v", err), "action offer-sent: "+errMsg)
	})

	t.Run("Send Invitation Credential", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, name []byte) error {
			require.Equal(t, "request-sent", string(name))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(RequestCredentialV3{
			Type: RequestCredentialMsgTypeV3,
		})

		messenger.EXPECT().Send(msg, Alice, Bob, gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, myDID, theirDID string, opts ...service.Opt) error {
				defer close(done)

				return nil
			})

		piid, err := svc.HandleOutbound(msg, Alice, Bob)
		require.NotEmpty(t, piid)
		require.NoError(t, err)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Send Invitation with error", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(RequestCredentialV3{
			Type: RequestCredentialMsgTypeV3,
		})

		messenger.EXPECT().Send(msg, Alice, Bob, gomock.Any()).Return(errors.New(errMsg))

		piid, err := svc.HandleOutbound(msg, Alice, Bob)
		require.Empty(t, piid)
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
		storeProvider.EXPECT().SetStoreConfig(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		messenger := serviceMocks.NewMockMessenger(ctrl)

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(messenger)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

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
		storeProvider.EXPECT().SetStoreConfig(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		messenger := serviceMocks.NewMockMessenger(ctrl)

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(messenger)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

		svc, err := New(provider)
		require.NoError(t, err)

		err = svc.ActionContinue("piID")
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
		storeProvider.EXPECT().SetStoreConfig(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		messenger := serviceMocks.NewMockMessenger(ctrl)

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(messenger)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

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
		storeProvider.EXPECT().SetStoreConfig(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		messenger := serviceMocks.NewMockMessenger(ctrl)

		provider := issuecredentialMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(messenger)
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

		svc, err := New(provider)
		require.NoError(t, err)

		err = svc.ActionStop("piID", nil)
		require.Contains(t, fmt.Sprintf("%v", err), "delete transitional payload: "+errMsg)
	})
}

func Test_stateFromName(t *testing.T) {
	require.Equal(t, stateFromName(stateNameStart, SpecV2), &start{})
	require.Equal(t, stateFromName(stateNameAbandoning, SpecV2), &abandoning{V: SpecV2})
	require.Equal(t, stateFromName(stateNameDone, SpecV2), &done{V: SpecV2})
	require.Equal(t, stateFromName(stateNameProposalReceived, SpecV2), &proposalReceived{V: SpecV2})
	require.Equal(t, stateFromName(stateNameOfferSent, SpecV2), &offerSent{V: SpecV2})
	require.Equal(t, stateFromName(stateNameRequestReceived, SpecV2), &requestReceived{V: SpecV2})
	require.Equal(t, stateFromName(stateNameCredentialIssued, SpecV2), &credentialIssued{V: SpecV2})
	require.Equal(t, stateFromName(stateNameProposalSent, SpecV2), &proposalSent{V: SpecV2})
	require.Equal(t, stateFromName(stateNameOfferReceived, SpecV2), &offerReceived{V: SpecV2})
	require.Equal(t, stateFromName(stateNameRequestSent, SpecV2), &requestSent{V: SpecV2})
	require.Equal(t, stateFromName(stateNameCredentialReceived, SpecV2), &credentialReceived{V: SpecV2})
	require.Equal(t, stateFromName("unknown", SpecV2), &noOp{})
}

func Test_nextState(t *testing.T) {
	next, err := nextState(service.NewDIDCommMsgMap(ProposeCredentialV2{
		Type: ProposeCredentialMsgTypeV2,
	}), true)
	require.NoError(t, err)
	require.Equal(t, next, &proposalSent{V: SpecV2})

	next, err = nextState(service.NewDIDCommMsgMap(ProposeCredentialV2{
		Type: ProposeCredentialMsgTypeV2,
	}), false)
	require.NoError(t, err)
	require.Equal(t, next, &proposalReceived{V: SpecV2})

	next, err = nextState(service.NewDIDCommMsgMap(OfferCredentialV2{
		Type: OfferCredentialMsgTypeV2,
	}), true)
	require.NoError(t, err)
	require.Equal(t, next, &offerSent{V: SpecV2})

	next, err = nextState(service.NewDIDCommMsgMap(OfferCredentialV2{
		Type: OfferCredentialMsgTypeV2,
	}), false)
	require.NoError(t, err)
	require.Equal(t, next, &offerReceived{V: SpecV2})

	next, err = nextState(service.NewDIDCommMsgMap(RequestCredentialV2{
		Type: RequestCredentialMsgTypeV2,
	}), true)
	require.NoError(t, err)
	require.Equal(t, next, &requestSent{V: SpecV2})

	next, err = nextState(service.NewDIDCommMsgMap(RequestCredentialV2{
		Type: RequestCredentialMsgTypeV2,
	}), false)
	require.NoError(t, err)
	require.Equal(t, next, &requestReceived{V: SpecV2})

	next, err = nextState(service.NewDIDCommMsgMap(IssueCredentialV2{
		Type: IssueCredentialMsgTypeV2,
	}), false)
	require.NoError(t, err)
	require.Equal(t, next, &credentialReceived{V: SpecV2})

	next, err = nextState(service.NewDIDCommMsgMap(model.Ack{
		Type: AckMsgTypeV2,
	}), false)
	require.NoError(t, err)
	require.Equal(t, next, &done{V: SpecV2})

	next, err = nextState(service.NewDIDCommMsgMap(model.ProblemReport{
		Type: ProblemReportMsgTypeV2,
	}), false)
	require.NoError(t, err)
	require.Equal(t, next, &abandoning{V: SpecV2})

	next, err = nextState(service.NewDIDCommMsgMap(struct{}{}), false)
	require.Error(t, err)
	require.Nil(t, next)
}

func TestService_Name(t *testing.T) {
	require.Equal(t, (*Service).Name(nil), Name)
}

func TestService_Accept(t *testing.T) {
	require.True(t, (*Service).Accept(nil, ProposeCredentialMsgTypeV2))
	require.True(t, (*Service).Accept(nil, OfferCredentialMsgTypeV2))
	require.True(t, (*Service).Accept(nil, RequestCredentialMsgTypeV2))
	require.True(t, (*Service).Accept(nil, IssueCredentialMsgTypeV2))
	require.True(t, (*Service).Accept(nil, AckMsgTypeV2))
	require.True(t, (*Service).Accept(nil, ProblemReportMsgTypeV2))
	require.False(t, (*Service).Accept(nil, "unknown"))
}

func TestService_canTriggerActionEvents(t *testing.T) {
	require.True(t, canTriggerActionEvents(service.NewDIDCommMsgMap(ProposeCredentialV2{
		Type: ProposeCredentialMsgTypeV2,
	})))

	require.True(t, canTriggerActionEvents(service.NewDIDCommMsgMap(OfferCredentialV2{
		Type: OfferCredentialMsgTypeV2,
	})))

	require.True(t, canTriggerActionEvents(service.NewDIDCommMsgMap(IssueCredentialV2{
		Type: IssueCredentialMsgTypeV2,
	})))

	require.True(t, canTriggerActionEvents(service.NewDIDCommMsgMap(RequestCredentialV2{
		Type: RequestCredentialMsgTypeV2,
	})))

	require.False(t, canTriggerActionEvents(service.NewDIDCommMsgMap(struct{}{})))
}
