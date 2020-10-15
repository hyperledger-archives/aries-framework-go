/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/protocol/middleware/presentproof"
	mocksvdr "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/framework/aries/api/vdr"
	mocksstore "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/store/verifiable"
)

// nolint: gochecknoglobals
var pubKey = did.PublicKey{
	ID: "key-1",
	Value: []byte{
		61, 133, 23, 17, 77, 132, 169, 196, 47, 203, 19, 71, 145, 144, 92, 145,
		131, 101, 36, 251, 89, 216, 117, 140, 132, 226, 78, 187, 59, 58, 200, 255,
	},
}

const vpJWS = "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiSldUIn0.eyJpc3MiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJqdGkiOiJ1cm46dXVpZDozOTc4MzQ0Zi04NTk2LTRjM2EtYTk3OC04ZmNhYmEzOTAzYzUiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbeyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImNyZWRlbnRpYWxTY2hlbWEiOltdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwidW5pdmVyc2l0eSI6Ik1JVCJ9LCJpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSIsIm5hbWUiOiJKYXlkZW4gRG9lIiwic3BvdXNlIjoiZGlkOmV4YW1wbGU6YzI3NmUxMmVjMjFlYmZlYjFmNzEyZWJjNmYxIn0sImV4cGlyYXRpb25EYXRlIjoiMjAyMC0wMS0wMVQxOToyMzoyNFoiLCJpZCI6Imh0dHA6Ly9leGFtcGxlLmVkdS9jcmVkZW50aWFscy8xODcyIiwiaXNzdWFuY2VEYXRlIjoiMjAxMC0wMS0wMVQxOToyMzoyNFoiLCJpc3N1ZXIiOnsiaWQiOiJkaWQ6ZXhhbXBsZTo3NmUxMmVjNzEyZWJjNmYxYzIyMWViZmViMWYiLCJuYW1lIjoiRXhhbXBsZSBVbml2ZXJzaXR5In0sInJlZmVyZW5jZU51bWJlciI6OC4zMjk0ODQ3ZSswNywidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl19XX19.RlO_1B-7qhQNwo2mmOFUWSa8A6hwaJrtq3q7yJDkKq4k6B-EJ-oyLNM6H_g2_nko2Yg9Im1CiROFm6nK12U_AQ" //nolint:lll

func TestSavePresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().VDRegistry().Return(nil).AnyTimes()
	provider.EXPECT().VerifiableStore().Return(nil).AnyTimes()

	next := presentproof.HandlerFunc(func(metadata presentproof.Metadata) error {
		return nil
	})

	t.Run("Ignores processing", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return("state-name")
		require.NoError(t, SavePresentation(provider)(next).Handle(metadata))
	})

	t.Run("Presentations not provided", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNamePresentationReceived)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.Presentation{
			Type: presentproof.PresentationMsgType,
		}))

		err := SavePresentation(provider)(next).Handle(metadata)
		require.EqualError(t, err, "presentations were not provided")
	})

	t.Run("Marshal presentation error", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNamePresentationReceived)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.Presentation{
			Type: presentproof.PresentationMsgType,
			PresentationsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: struct{ C chan int }{}}},
			},
		}))

		err := SavePresentation(provider)(next).Handle(metadata)
		require.Contains(t, fmt.Sprintf("%v", err), "json: unsupported type")
	})

	t.Run("Decode error", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNamePresentationReceived)
		metadata.EXPECT().Message().Return(service.DIDCommMsgMap{"@type": map[int]int{}})

		err := SavePresentation(provider)(next).Handle(metadata)
		require.Contains(t, fmt.Sprintf("%v", err), "got unconvertible type")
	})

	t.Run("Invalid presentation", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNamePresentationReceived)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.Presentation{
			Type: presentproof.PresentationMsgType,
			PresentationsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: &verifiable.Presentation{
					Context: []string{"https://www.w3.org/2018/presentation/v1"},
				}}},
			},
		}))

		err := SavePresentation(provider)(next).Handle(metadata)
		require.Contains(t, fmt.Sprintf("%v", err), "to verifiable presentation")
	})

	t.Run("DB error", func(t *testing.T) {
		const (
			vcName = "vp-name"
			errMsg = "error message"
		)

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNamePresentationReceived)
		metadata.EXPECT().PresentationNames().Return([]string{vcName}).Times(2)
		metadata.EXPECT().Properties().Return(map[string]interface{}{
			myDIDKey:    myDIDKey,
			theirDIDKey: theirDIDKey,
		})
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.Presentation{
			Type: presentproof.PresentationMsgType,
			PresentationsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{Base64: base64.StdEncoding.EncodeToString([]byte(vpJWS))}},
			},
		}))

		verifiableStore := mocksstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SavePresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(errors.New(errMsg))

		registry := mocksvdr.NewMockRegistry(ctrl)
		registry.EXPECT().Resolve("did:example:ebfeb1f712ebc6f1c276e12ec21").Return(&did.Doc{
			PublicKey: []did.PublicKey{pubKey},
		}, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRegistry().Return(registry).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore)

		require.EqualError(t, SavePresentation(provider)(next).Handle(metadata), "save presentation: "+errMsg)
	})

	t.Run("No DIDs", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNamePresentationReceived)
		metadata.EXPECT().Properties().Return(map[string]interface{}{})
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.Presentation{
			Type: presentproof.PresentationMsgType,
			PresentationsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{Base64: base64.StdEncoding.EncodeToString([]byte(vpJWS))}},
			},
		}))

		registry := mocksvdr.NewMockRegistry(ctrl)
		registry.EXPECT().Resolve("did:example:ebfeb1f712ebc6f1c276e12ec21").Return(&did.Doc{
			PublicKey: []did.PublicKey{pubKey},
		}, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRegistry().Return(registry).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(mocksstore.NewMockStore(ctrl))

		require.EqualError(t, SavePresentation(provider)(next).Handle(metadata), "myDID or theirDID is absent")
	})

	t.Run("Success (no ID)", func(t *testing.T) {
		vpJWSNoID := "eyJhbGciOiJFZERTQSIsImtpZCI6IiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkaWQ6ZXhhbXBsZTo0YTU3NTQ2OTczNDM2ZjZmNmM0YTRhNTc1NzMiLCJpc3MiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbeyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImNyZWRlbnRpYWxTY2hlbWEiOltdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwidW5pdmVyc2l0eSI6Ik1JVCJ9LCJpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSIsIm5hbWUiOiJKYXlkZW4gRG9lIiwic3BvdXNlIjoiZGlkOmV4YW1wbGU6YzI3NmUxMmVjMjFlYmZlYjFmNzEyZWJjNmYxIn0sImV4cGlyYXRpb25EYXRlIjoiMjAyMC0wMS0wMVQxOToyMzoyNFoiLCJpZCI6Imh0dHA6Ly9leGFtcGxlLmVkdS9jcmVkZW50aWFscy8xODcyIiwiaXNzdWFuY2VEYXRlIjoiMjAxMC0wMS0wMVQxOToyMzoyNFoiLCJpc3N1ZXIiOnsiaWQiOiJkaWQ6ZXhhbXBsZTo3NmUxMmVjNzEyZWJjNmYxYzIyMWViZmViMWYiLCJuYW1lIjoiRXhhbXBsZSBVbml2ZXJzaXR5In0sInJlZmVyZW5jZU51bWJlciI6ODMyOTQ4NDcsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdfV19fQ.VaULMC_bFEI46jPLX7T8BW9liQ88JfCu0BeAxUkEIqjk-K2GFAbrP1WOJyJIXZZ-5J_nM7LNZX6mxbmhcj--Dw" //nolint:lll

		props := map[string]interface{}{
			myDIDKey:    myDIDKey,
			theirDIDKey: theirDIDKey,
		}

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNamePresentationReceived)
		metadata.EXPECT().PresentationNames().Return(nil)
		metadata.EXPECT().Properties().Return(props)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.Presentation{
			Type: presentproof.PresentationMsgType,
			PresentationsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{Base64: base64.StdEncoding.EncodeToString([]byte(vpJWSNoID))}},
			},
		}))

		verifiableStore := mocksstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SavePresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)

		registry := mocksvdr.NewMockRegistry(ctrl)
		registry.EXPECT().Resolve("did:example:ebfeb1f712ebc6f1c276e12ec21").Return(&did.Doc{
			PublicKey: []did.PublicKey{pubKey},
		}, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRegistry().Return(registry).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore)

		require.NoError(t, SavePresentation(provider)(next).Handle(metadata))
		require.Equal(t, len(props["names"].([]string)), 1)
		require.NotEmpty(t, props["names"].([]string)[0])
	})

	t.Run("Success", func(t *testing.T) {
		const vcName = "vc-name"

		props := map[string]interface{}{
			myDIDKey:    myDIDKey,
			theirDIDKey: theirDIDKey,
		}

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNamePresentationReceived)
		metadata.EXPECT().PresentationNames().Return([]string{vcName}).Times(2)
		metadata.EXPECT().Properties().Return(props)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.Presentation{
			Type: presentproof.PresentationMsgType,
			PresentationsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{Base64: base64.StdEncoding.EncodeToString([]byte(vpJWS))}},
			},
		}))

		verifiableStore := mocksstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SavePresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)

		registry := mocksvdr.NewMockRegistry(ctrl)
		registry.EXPECT().Resolve("did:example:ebfeb1f712ebc6f1c276e12ec21").Return(&did.Doc{
			PublicKey: []did.PublicKey{pubKey},
		}, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRegistry().Return(registry).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore)

		require.NoError(t, SavePresentation(provider)(next).Handle(metadata))
		require.Equal(t, props["names"], []string{vcName})
	})
}
