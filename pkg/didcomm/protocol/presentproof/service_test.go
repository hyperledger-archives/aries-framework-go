/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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
	serviceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/common/service"
	presentproofMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/protocol/presentproof"
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/spi/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
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
		storeProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)
		storeProvider.EXPECT().SetStoreConfig(Name, gomock.Any()).Return(nil)

		provider := presentproofMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider).Times(2)

		svc, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, svc)
	})

	t.Run("Error open store", func(t *testing.T) {
		const errMsg = "error"

		storeProvider := storageMocks.NewMockProvider(ctrl)
		storeProvider.EXPECT().OpenStore(Name).Return(nil, errors.New(errMsg))

		provider := presentproofMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storeProvider)

		svc, err := New(provider)
		require.Contains(t, fmt.Sprintf("%v", err), errMsg)
		require.Nil(t, svc)
	})
}

func TestService_Initialize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("success", func(t *testing.T) {
		storeProvider := storageMocks.NewMockProvider(ctrl)
		storeProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)
		storeProvider.EXPECT().SetStoreConfig(Name, gomock.Any()).Return(nil)

		provider := presentproofMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider).Times(2)

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

func TestService_Use(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Success (one function)", func(t *testing.T) {
		storeProvider := storageMocks.NewMockProvider(ctrl)
		storeProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil).Times(1)
		storeProvider.EXPECT().SetStoreConfig(Name, gomock.Any()).Return(nil)

		provider := presentproofMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider).Times(2)

		svc, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, svc)

		meta := &metaData{
			state: &done{},
			msgClone: service.NewDIDCommMsgMap(struct {
				Type string `json:"@type"`
			}{
				Type: PresentationMsgTypeV2,
			}),
			presentation:          &PresentationV2{Type: PresentationMsgTypeV2},
			presentationV3:        &PresentationV3{Type: PresentationMsgTypeV3},
			proposePresentation:   &ProposePresentationV2{Type: ProposePresentationMsgTypeV2},
			proposePresentationV3: &ProposePresentationV3{Type: ProposePresentationMsgTypeV3},
			request:               &RequestPresentationV2{Type: RequestPresentationMsgTypeV2},
			requestV3:             &RequestPresentationV3{Type: RequestPresentationMsgTypeV3},
			presentationNames:     []string{"name"},
		}
		var executed bool
		svc.Use(func(next Handler) Handler {
			return HandlerFunc(func(metadata Metadata) error {
				require.Equal(t, meta.msgClone, metadata.Message())
				require.Equal(t, metadata.Message().Type(), PresentationMsgTypeV2)
				require.Equal(t, meta.presentation, metadata.Presentation())
				require.Equal(t, meta.presentationV3, metadata.PresentationV3())
				require.Equal(t, meta.proposePresentation, metadata.ProposePresentation())
				require.Equal(t, meta.proposePresentationV3, metadata.ProposePresentationV3())
				require.Equal(t, meta.request, metadata.RequestPresentation())
				require.Equal(t, meta.requestV3, metadata.RequestPresentationV3())
				require.Equal(t, meta.presentationNames, metadata.PresentationNames())
				require.Equal(t, meta.state.Name(), metadata.StateName())
				require.Nil(t, metadata.GetAddProofFn())

				executed = true
				return next.Handle(metadata)
			})
		})

		_, _, err = svc.execute(meta.state, meta)
		require.NoError(t, err)
		require.True(t, executed)
	})

	t.Run("Success (two function)", func(t *testing.T) {
		storeProvider := storageMocks.NewMockProvider(ctrl)
		storeProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil).Times(1)
		storeProvider.EXPECT().SetStoreConfig(Name, gomock.Any()).Return(nil)

		provider := presentproofMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider).Times(2)

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

		_, _, err = svc.execute(&done{}, &metaData{})
		require.NoError(t, err)
	})

	t.Run("Failed", func(t *testing.T) {
		storeProvider := storageMocks.NewMockProvider(ctrl)
		storeProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil).Times(1)
		storeProvider.EXPECT().SetStoreConfig(Name, gomock.Any()).Return(nil)

		provider := presentproofMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider).Times(2)

		svc, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, svc)

		const msgErr = "error message"
		svc.Use(func(next Handler) Handler {
			return HandlerFunc(func(metadata Metadata) error {
				return errors.New(msgErr)
			})
		})

		_, _, err = svc.execute(&done{}, &metaData{})
		require.EqualError(t, err, "middleware: "+msgErr)
	})
}

func TestService_ActionContinue(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const errMsg = "error"

	store := storageMocks.NewMockStore(ctrl)
	storeProvider := storageMocks.NewMockProvider(ctrl)
	storeProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil).AnyTimes()
	storeProvider.EXPECT().SetStoreConfig(Name, gomock.Any()).Return(nil).AnyTimes()

	provider := presentproofMocks.NewMockProvider(ctrl)
	provider.EXPECT().Messenger().Return(nil).AnyTimes()
	provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

	t.Run("Error transitional payload (get)", func(t *testing.T) {
		store.EXPECT().Get(gomock.Any()).Return(nil, errors.New(errMsg))

		svc, err := New(provider)
		require.NoError(t, err)

		err = svc.ActionContinue("piID", nil)
		require.Contains(t, fmt.Sprintf("%v", err), "get transitional payload: store get: "+errMsg)
	})

	t.Run("Error transitional payload (delete)", func(t *testing.T) {
		store.EXPECT().Get(gomock.Any()).Return([]byte(`{}`), nil)
		store.EXPECT().Delete(gomock.Any()).Return(errors.New(errMsg))

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
		storeProvider.EXPECT().OpenStore(Name).Return(store, nil).AnyTimes()
		storeProvider.EXPECT().SetStoreConfig(Name, gomock.Any()).Return(nil)

		provider := presentproofMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider).Times(2)

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
		storeProvider.EXPECT().OpenStore(Name).Return(store, nil).AnyTimes()
		storeProvider.EXPECT().SetStoreConfig(Name, gomock.Any()).Return(nil)

		provider := presentproofMocks.NewMockProvider(ctrl)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().StorageProvider().Return(storeProvider).Times(2)

		svc, err := New(provider)
		require.NoError(t, err)

		err = svc.ActionStop("piID", nil)
		require.Contains(t, fmt.Sprintf("%v", err), "delete transitional payload: "+errMsg)
	})
}

// nolint: gocyclo,gocognit
func TestService_HandleInboundOutbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const errMsg = "error"

	initMocks := func(controller *gomock.Controller) (
		store *storageMocks.MockStore,
		messenger *serviceMocks.MockMessenger,
		provider *presentproofMocks.MockProvider,
	) {
		store = storageMocks.NewMockStore(controller)

		storeProvider := storageMocks.NewMockProvider(controller)
		storeProvider.EXPECT().OpenStore(Name).Return(store, nil).AnyTimes()
		storeProvider.EXPECT().SetStoreConfig(Name, gomock.Any()).Return(nil).AnyTimes()

		messenger = serviceMocks.NewMockMessenger(controller)

		provider = presentproofMocks.NewMockProvider(controller)
		provider.EXPECT().Messenger().Return(messenger).AnyTimes()
		provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

		return store, messenger, provider
	}

	t.Run("No clients", func(t *testing.T) {
		_, _, provider := initMocks(ctrl)

		svc, err := New(provider)
		require.NoError(t, err)

		_, err = svc.HandleInbound(randomInboundMessage(""), service.EmptyDIDCommContext())
		require.Contains(t, fmt.Sprintf("%v", err), "no clients")
	})

	t.Run("DB error", func(t *testing.T) {
		store, _, provider := initMocks(ctrl)

		store.EXPECT().Get(gomock.Any()).Return(nil, errors.New(errMsg)).AnyTimes()

		svc, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, svc.RegisterActionEvent(make(chan<- service.DIDCommAction)))

		msg := service.NewDIDCommMsgMap(struct {
			ID     string           `json:"@id"`
			Type   string           `json:"@type"`
			Thread decorator.Thread `json:"~thread"`
		}{ID: "ID", Type: "type", Thread: decorator.Thread{PID: "PID"}})
		msg.SetID(uuid.New().String())

		_, err = svc.HandleInbound(msg, service.EmptyDIDCommContext())
		require.Contains(t, fmt.Sprintf("%v", err),
			"buildMetaData: current internal data and PIID: current internal data: "+errMsg)
	})

	t.Run("DB error (saveTransitionalPayload)", func(t *testing.T) {
		store, _, provider := initMocks(ctrl)

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New(errMsg))

		svc, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, svc.RegisterActionEvent(make(chan<- service.DIDCommAction)))

		_, err = svc.HandleInbound(randomInboundMessage(RequestPresentationMsgTypeV2), service.EmptyDIDCommContext())
		require.Contains(t, fmt.Sprintf("%v", err), "save transitional payload: "+errMsg)
	})

	t.Run("Unrecognized msgType", func(t *testing.T) {
		store, _, provider := initMocks(ctrl)

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()

		svc, err := New(provider)
		require.NoError(t, err)

		require.NoError(t, svc.RegisterActionEvent(make(chan<- service.DIDCommAction)))

		msg := service.NewDIDCommMsgMap(struct{}{})
		msg.SetID(uuid.New().String())
		msg["@type"] = "type"

		_, err = svc.HandleInbound(msg, service.EmptyDIDCommContext())
		require.Contains(t, fmt.Sprintf("%v", err), "buildMetaData: nextState: unrecognized msgType: ")
	})

	t.Run("Invalid state transition", func(t *testing.T) {
		_, _, provider := initMocks(ctrl)

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		chState := make(chan service.StateMsg, 2)
		require.NoError(t, svc.RegisterMsgEvent(chState))

		_, err = svc.HandleInbound(service.NewDIDCommMsgMap(model.ProblemReport{
			Type: ProblemReportMsgTypeV2,
		}), service.EmptyDIDCommContext())
		require.Contains(t, fmt.Sprintf("%v", err), "buildMetaData: invalid state transition")
	})

	t.Run("Receive Invitation Presentation (Stop)", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})
		errChan := make(chan error)

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

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err := json.Marshal(&internalData{StateName: "abandoned", ProtocolVersion: version2})
			require.NoError(t, err)
			require.True(t, bytes.Equal(src, data))

			if !bytes.Equal(src, data) {
				errChan <- fmt.Errorf("data: %s\nsrc: %s", string(data), string(src))
			}
			return nil
		})
		store.EXPECT().Delete(gomock.Any()).Return(errors.New(errMsg))

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(
			randomInboundMessage(RequestPresentationMsgTypeV2), service.NewDIDCommContext(Alice, Bob, nil))
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
		case e := <-errChan:
			t.Error(e)
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Invitation Presentation (continue with presentation)", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &PresentationV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, PresentationMsgTypeV2, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err := json.Marshal(&internalData{StateName: "request-received", ProtocolVersion: version2})
			require.NoError(t, err)
			require.Equal(t, string(src), string(data))

			return nil
		})
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err := json.Marshal(&internalData{StateName: "presentation-sent", ProtocolVersion: version2})
			require.NoError(t, err)
			require.Equal(t, string(src), string(data))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := randomInboundMessage(RequestPresentationMsgTypeV2)
		msg["will_confirm"] = true

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithMultiOptions(WithPresentation(&PresentationParams{}), WithAddProofFn(nil)))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Invitation Presentation (continue with presentation) async", func(t *testing.T) {
		_, messenger, _ := initMocks(ctrl)

		done := make(chan struct{})

		memProvider := mem.NewProvider()

		newProvider := presentproofMocks.NewMockProvider(ctrl)
		newProvider.EXPECT().Messenger().Return(messenger)
		newProvider.EXPECT().StorageProvider().Return(memProvider).Times(2)

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &PresentationV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, PresentationMsgTypeV2, r.Type)

				return nil
			})

		svc, err := New(newProvider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := randomInboundMessage(RequestPresentationMsgTypeV2)
		msg["will_confirm"] = true

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		actions, err := svc.Actions()
		require.NoError(t, err)
		for _, action := range actions {
			require.Equal(t, action.MyDID, Alice)
			require.Equal(t, action.TheirDID, Bob)
			require.NoError(t, svc.ActionContinue(action.PIID, WithPresentation(&PresentationParams{})))
		}

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Invitation Presentation (continue with presentation) async v3", func(t *testing.T) {
		_, messenger, _ := initMocks(ctrl)

		done := make(chan struct{})

		memProvider := mem.NewProvider()

		newProvider := presentproofMocks.NewMockProvider(ctrl)
		newProvider.EXPECT().Messenger().Return(messenger)
		newProvider.EXPECT().StorageProvider().Return(memProvider).Times(2)

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &PresentationV3{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, PresentationMsgTypeV3, r.Type)

				return nil
			})

		svc, err := New(newProvider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := randomInboundMessageV3(RequestPresentationMsgTypeV3)

		msg["data"] = map[string]interface{}{
			"will_confirm": true,
		}

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		actions, err := svc.Actions()
		require.NoError(t, err)
		for _, action := range actions {
			require.Equal(t, action.MyDID, Alice)
			require.Equal(t, action.TheirDID, Bob)
			require.NoError(t, svc.ActionContinue(action.PIID, WithPresentation(&PresentationParams{})))
		}

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Invitation Presentation (Stop) async", func(t *testing.T) {
		_, messenger, _ := initMocks(ctrl)

		done := make(chan struct{})

		memProvider := mem.NewProvider()

		newProvider := presentproofMocks.NewMockProvider(ctrl)
		newProvider.EXPECT().Messenger().Return(messenger)
		newProvider.EXPECT().StorageProvider().Return(memProvider).Times(2)

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

		_, err = svc.HandleInbound(
			randomInboundMessage(RequestPresentationMsgTypeV2), service.NewDIDCommContext(Alice, Bob, nil))
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

	t.Run("Receive Invitation Presentation (continue with proposal)", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &ProposePresentationV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, ProposePresentationMsgTypeV2, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err := json.Marshal(&internalData{StateName: "request-received", ProtocolVersion: version2})
			require.NoError(t, err)
			require.Equal(t, string(src), string(data))

			return nil
		})
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err := json.Marshal(&internalData{StateName: "proposal-sent", ProtocolVersion: version2})
			require.NoError(t, err)
			require.Equal(t, string(src), string(data))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(
			randomInboundMessage(RequestPresentationMsgTypeV2), service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithProposePresentation(&ProposePresentationParams{}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Invitation Presentation (continue with proposal) v3", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &ProposePresentationV3{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, ProposePresentationMsgTypeV3, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err := json.Marshal(&internalData{StateName: "request-received", ProtocolVersion: version3})
			require.NoError(t, err)
			require.Equal(t, string(src), string(data))

			return nil
		})
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err := json.Marshal(&internalData{StateName: "proposal-sent", ProtocolVersion: version3})
			require.NoError(t, err)
			require.Equal(t, string(src), string(data))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(
			randomInboundMessageV3(RequestPresentationMsgTypeV3), service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithProposePresentation(&ProposePresentationParams{}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Propose Presentation (continue)", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &RequestPresentationV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, RequestPresentationMsgTypeV2, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err := json.Marshal(&internalData{StateName: "proposal-received", ProtocolVersion: version2})
			require.NoError(t, err)
			require.Equal(t, string(src), string(data))

			return nil
		})

		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err := json.Marshal(&internalData{StateName: "request-sent", ProtocolVersion: version2})
			require.NoError(t, err)
			require.Equal(t, string(src), string(data))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(
			randomInboundMessage(ProposePresentationMsgTypeV2),
			service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithRequestPresentation(&RequestPresentationParams{}))

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Receive Propose Presentation (continue) v3", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				defer close(done)

				r := &RequestPresentationV3{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, RequestPresentationMsgTypeV3, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err := json.Marshal(&internalData{StateName: "proposal-received", ProtocolVersion: version3})
			require.NoError(t, err)
			require.Equal(t, string(src), string(data))

			return nil
		})

		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err := json.Marshal(&internalData{StateName: "request-sent", ProtocolVersion: version3})
			require.NoError(t, err)
			require.Equal(t, string(src), string(data))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(
			randomInboundMessageV3(ProposePresentationMsgTypeV3),
			service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithRequestPresentation(&RequestPresentationParams{}))

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

		src, err := json.Marshal(&internalData{StateName: "request-sent", ProtocolVersion: version2})
		require.NoError(t, err)

		store.EXPECT().Get(gomock.Any()).Return(src, nil).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			defer close(done)

			src, err = json.Marshal(&internalData{StateName: "abandoned", ProtocolVersion: version2})
			require.NoError(t, err)
			require.Equal(t, string(src), string(data))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(randomInboundMessage(ProblemReportMsgTypeV2), service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		action := <-ch

		properties, ok := action.Properties.(*eventProps)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Continue(WithRequestPresentation(&RequestPresentationParams{}))

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

		src, err := json.Marshal(&internalData{StateName: "request-sent"})
		require.NoError(t, err)

		store.EXPECT().Get(gomock.Any()).Return(src, nil).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			defer close(done)

			src, err = json.Marshal(&internalData{StateName: "abandoned"})
			require.NoError(t, err)
			require.Equal(t, src, data)

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(randomInboundMessage(ProblemReportMsgTypeV2), service.NewDIDCommContext(Alice, Bob, nil))
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

	t.Run("Receive Propose Presentation (continue without request)", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().
			ReplyToNested(gomock.Any(), gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
				defer close(done)

				r := &model.ProblemReport{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, codeInternalError, r.Description.Code)
				require.Equal(t, ProblemReportMsgTypeV2, r.Type)

				return nil
			})

		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err := json.Marshal(&internalData{StateName: "proposal-received", ProtocolVersion: version2})
			require.NoError(t, err)
			require.Equal(t, string(src), string(data))

			return nil
		})

		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err := json.Marshal(&internalData{StateName: "abandoned", ProtocolVersion: version2})
			require.NoError(t, err)
			require.Equal(t, string(src), string(data))

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(
			randomInboundMessage(ProposePresentationMsgTypeV2),
			service.NewDIDCommContext(Alice, Bob, nil))
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

	t.Run("Receive Presentation (continue)", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				r := &model.Ack{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, AckMsgTypeV2, r.Type)

				return nil
			})

		src, err := json.Marshal(&internalData{AckRequired: true, StateName: "request-sent"})
		require.NoError(t, err)

		store.EXPECT().Get(gomock.Any()).Return(src, nil).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err = json.Marshal(&internalData{AckRequired: true, StateName: "presentation-received"})
			require.NoError(t, err)
			require.Equal(t, src, data)

			return nil
		})

		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			defer close(done)

			src, err = json.Marshal(&internalData{AckRequired: true, StateName: "done"})
			require.NoError(t, err)
			require.Equal(t, src, data)

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(PresentationV2{
			Type: PresentationMsgTypeV2,
			PresentationsAttach: []decorator.Attachment{{
				Data: decorator.AttachmentData{
					Base64: base64.StdEncoding.EncodeToString([]byte(`{}`)),
				},
			}},
		})
		msg.SetID(uuid.New().String())

		msg["~thread"] = decorator.Thread{ID: uuid.New().String()}

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
		case <-time.After(time.Second * 10):
			t.Error("timeout")
		}
	})

	t.Run("Receive Presentation (continue) v3", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		messenger.EXPECT().ReplyToMsg(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_, msg service.DIDCommMsgMap, _, _ string, opts ...service.Opt) error {
				r := &model.AckV2{}
				require.NoError(t, msg.Decode(r))
				require.Equal(t, AckMsgTypeV3, r.Type)

				return nil
			})

		src, err := json.Marshal(&internalData{AckRequired: true, StateName: "request-sent"})
		require.NoError(t, err)

		store.EXPECT().Get(gomock.Any()).Return(src, nil).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().Delete(gomock.Any()).Return(nil)
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, err = json.Marshal(&internalData{AckRequired: true, StateName: "presentation-received"})
			require.NoError(t, err)
			require.Equal(t, src, data)

			return nil
		})

		store.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			defer close(done)

			src, err = json.Marshal(&internalData{AckRequired: true, StateName: "done"})
			require.NoError(t, err)
			require.Equal(t, src, data)

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		msg := service.NewDIDCommMsgMap(PresentationV3{
			Type: PresentationMsgTypeV3,
			Attachments: []decorator.AttachmentV2{{
				Data: decorator.AttachmentData{
					Base64: base64.StdEncoding.EncodeToString([]byte(`{}`)),
				},
			}},
		})
		msg.SetID(uuid.New().String())
		msg.SetThread(uuid.New().String(), "", service.WithVersion(service.V2))

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
		case <-time.After(time.Second * 10):
			t.Error("timeout")
		}
	})

	t.Run("Receive Ack", func(t *testing.T) {
		store, _, provider := initMocks(ctrl)

		done := make(chan struct{})

		src, err := json.Marshal(&internalData{StateName: "presentation-sent"})
		require.NoError(t, err)

		store.EXPECT().Get(gomock.Any()).Return(src, nil).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			defer close(done)

			src, err = json.Marshal(&internalData{StateName: "done"})
			require.NoError(t, err)
			require.Equal(t, src, data)

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		ch := make(chan service.DIDCommAction, 1)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(randomInboundMessage(AckMsgTypeV2), service.NewDIDCommContext(Alice, Bob, nil))
		require.NoError(t, err)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Send Invitation Presentation", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		src, err := json.Marshal(&internalData{StateName: "proposal-received"})
		require.NoError(t, err)
		store.EXPECT().Get(gomock.Any()).Return(src, nil).AnyTimes()

		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			src, e := json.Marshal(&internalData{StateName: "request-sent"})
			require.NoError(t, e)
			require.Equal(t, src, data)

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(RequestPresentationV2{
			Type: RequestPresentationMsgTypeV2,
		})

		messenger.EXPECT().Send(gomock.Any(), Alice, Bob, gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, myDID, theirDID string, opts ...service.Opt) error {
				require.NotEmpty(t, msg.ID())
				require.Equal(t, RequestPresentationMsgTypeV2, msg.Type())

				defer close(done)

				return nil
			})

		_, err = svc.HandleOutbound(msg, Alice, Bob)
		require.NoError(t, err)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Send Invitation Presentation with error", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		src, err := json.Marshal(&internalData{StateName: "proposal-received"})
		require.NoError(t, err)
		store.EXPECT().Get(gomock.Any()).Return(src, nil).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(RequestPresentationV2{
			Type: RequestPresentationMsgTypeV2,
		})

		messenger.EXPECT().Send(gomock.Any(), Alice, Bob, gomock.Any()).Return(errors.New(errMsg))

		_, err = svc.HandleOutbound(msg, Alice, Bob)
		require.Contains(t, fmt.Sprintf("%v", err), "action request-sent: "+errMsg)
	})

	t.Run("Send Proposal", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		done := make(chan struct{})

		src, err := json.Marshal(&internalData{StateName: "request-received"})
		require.NoError(t, err)
		store.EXPECT().Get(gomock.Any()).Return(src, nil).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ string, data []byte) error {
			s, e := json.Marshal(&internalData{StateName: "proposal-sent"})
			require.NoError(t, e)
			require.Equal(t, s, data)

			return nil
		})

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(ProposePresentationV2{
			Type: ProposePresentationMsgTypeV2,
		})

		messenger.EXPECT().Send(gomock.Any(), Alice, Bob, gomock.Any()).
			Do(func(msg service.DIDCommMsgMap, myDID, theirDID string, opts ...service.Opt) error {
				defer close(done)

				require.NotEmpty(t, msg.ID())
				require.Equal(t, ProposePresentationMsgTypeV2, msg.Type())

				return nil
			})

		_, err = svc.HandleOutbound(msg, Alice, Bob)
		require.NoError(t, err)

		select {
		case <-done:
			return
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})

	t.Run("Send Proposal with error", func(t *testing.T) {
		store, messenger, provider := initMocks(ctrl)

		src, err := json.Marshal(&internalData{StateName: "request-received"})
		require.NoError(t, err)
		store.EXPECT().Get(gomock.Any()).Return(src, nil).AnyTimes()
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)

		svc, err := New(provider)
		require.NoError(t, err)

		msg := service.NewDIDCommMsgMap(ProposePresentationV2{
			Type: ProposePresentationMsgTypeV2,
		})

		messenger.EXPECT().Send(gomock.Any(), Alice, Bob, gomock.Any()).Return(errors.New(errMsg))

		_, err = svc.HandleOutbound(msg, Alice, Bob)
		require.Contains(t, fmt.Sprintf("%v", err), "action proposal-sent: "+errMsg)
	})
}

func Test_stateFromName(t *testing.T) {
	require.Equal(t, stateFromName(stateNameStart, SpecV2), &start{})
	require.Equal(t, stateFromName(StateNameAbandoned, SpecV2), &abandoned{V: SpecV2})
	require.Equal(t, stateFromName(StateNameDone, SpecV2), &done{V: SpecV2})
	require.Equal(t, stateFromName(stateNameRequestSent, SpecV2), &requestSent{V: SpecV2})
	require.Equal(t, stateFromName(stateNamePresentationReceived, SpecV2), &presentationReceived{V: SpecV2})
	require.Equal(t, stateFromName(stateNameProposalReceived, SpecV2), &proposalReceived{V: SpecV2})
	require.Equal(t, stateFromName(stateNameRequestReceived, SpecV2), &requestReceived{V: SpecV2})
	require.Equal(t, stateFromName(stateNamePresentationSent, SpecV2), &presentationSent{V: SpecV2})
	require.Equal(t, stateFromName(stateNameProposalSent, SpecV2), &proposalSent{V: SpecV2})
	require.Equal(t, stateFromName("unknown", SpecV2), &noOp{})
}

func TestService_Name(t *testing.T) {
	require.Equal(t, (*Service).Name(nil), Name)
}

func TestService_Accept(t *testing.T) {
	require.True(t, (*Service).Accept(nil, ProposePresentationMsgTypeV2))
	require.True(t, (*Service).Accept(nil, RequestPresentationMsgTypeV2))
	require.True(t, (*Service).Accept(nil, PresentationMsgTypeV2))
	require.True(t, (*Service).Accept(nil, AckMsgTypeV2))
	require.True(t, (*Service).Accept(nil, ProblemReportMsgTypeV2))
	require.False(t, (*Service).Accept(nil, "unknown"))
}

func TestService_canTriggerActionEvents(t *testing.T) {
	require.True(t, canTriggerActionEvents(service.NewDIDCommMsgMap(ProposePresentationV2{
		Type: ProposePresentationMsgTypeV2,
	})))

	require.True(t, canTriggerActionEvents(service.NewDIDCommMsgMap(RequestPresentationV2{
		Type: RequestPresentationMsgTypeV2,
	})))

	require.True(t, canTriggerActionEvents(service.NewDIDCommMsgMap(PresentationV2{
		Type: PresentationMsgTypeV2,
	})))

	require.False(t, canTriggerActionEvents(service.NewDIDCommMsgMap(struct{}{})))
}

func Test_getTransitionalPayload(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storageMocks.NewMockStore(ctrl)

	storeProvider := storageMocks.NewMockProvider(ctrl)
	storeProvider.EXPECT().OpenStore(Name).Return(store, nil).AnyTimes()
	storeProvider.EXPECT().SetStoreConfig(Name, gomock.Any()).Return(nil)

	provider := presentproofMocks.NewMockProvider(ctrl)
	provider.EXPECT().Messenger().Return(nil).AnyTimes()
	provider.EXPECT().StorageProvider().Return(storeProvider).AnyTimes()

	store.EXPECT().Get(fmt.Sprintf(transitionalPayloadKey, "ID")).Return([]byte(`[]`), nil)

	svc, err := New(provider)
	require.NoError(t, err)

	res, err := svc.getTransitionalPayload("ID")
	require.Nil(t, res)
	require.Contains(t, fmt.Sprintf("%v", err), "unmarshal transitional payload")
}

func Test_nextState(t *testing.T) {
	next, err := nextState(service.NewDIDCommMsgMap(RequestPresentationV2{
		Type: RequestPresentationMsgTypeV2,
	}), outboundMessage)
	require.NoError(t, err)
	require.Equal(t, next, &requestSent{V: SpecV2})

	next, err = nextState(randomInboundMessage(RequestPresentationMsgTypeV2), inboundMessage)
	require.NoError(t, err)
	require.Equal(t, next, &requestReceived{V: SpecV2})

	next, err = nextState(service.NewDIDCommMsgMap(ProposePresentationV2{
		Type: ProposePresentationMsgTypeV2,
	}), outboundMessage)
	require.NoError(t, err)
	require.Equal(t, next, &proposalSent{V: SpecV2})

	next, err = nextState(randomInboundMessage(ProposePresentationMsgTypeV2), inboundMessage)
	require.NoError(t, err)
	require.Equal(t, next, &proposalReceived{V: SpecV2})

	next, err = nextState(randomInboundMessage(PresentationMsgTypeV2), inboundMessage)
	require.NoError(t, err)
	require.Equal(t, next, &presentationReceived{V: SpecV2})

	next, err = nextState(randomInboundMessage(AckMsgTypeV2), inboundMessage)
	require.NoError(t, err)
	require.Equal(t, next, &done{V: SpecV2, properties: map[string]interface{}{}})

	next, err = nextState(randomInboundMessage(ProblemReportMsgTypeV2), inboundMessage)
	require.NoError(t, err)
	require.Equal(t, next, &abandoned{V: SpecV2, properties: map[string]interface{}{}})

	next, err = nextState(service.NewDIDCommMsgMap(struct{}{}), outboundMessage)
	require.Error(t, err)
	require.Nil(t, next)
}
