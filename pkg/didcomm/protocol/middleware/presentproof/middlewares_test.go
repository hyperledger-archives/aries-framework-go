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
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/protocol/middleware/presentproof"
	mocksvdr "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/framework/aries/api/vdr"
	mocksstore "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/store/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
)

// nolint: gochecknoglobals
var pubKey = did.VerificationMethod{
	ID: "key-1",
	Value: []byte{
		61, 133, 23, 17, 77, 132, 169, 196, 47, 203, 19, 71, 145, 144, 92, 145,
		131, 101, 36, 251, 89, 216, 117, 140, 132, 226, 78, 187, 59, 58, 200, 255,
	},
}

const vpJWS = "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiSldUIn0.eyJpc3MiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJqdGkiOiJ1cm46dXVpZDozOTc4MzQ0Zi04NTk2LTRjM2EtYTk3OC04ZmNhYmEzOTAzYzUiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbeyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImNyZWRlbnRpYWxTY2hlbWEiOltdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwidW5pdmVyc2l0eSI6Ik1JVCJ9LCJpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSIsIm5hbWUiOiJKYXlkZW4gRG9lIiwic3BvdXNlIjoiZGlkOmV4YW1wbGU6YzI3NmUxMmVjMjFlYmZlYjFmNzEyZWJjNmYxIn0sImV4cGlyYXRpb25EYXRlIjoiMjAyMC0wMS0wMVQxOToyMzoyNFoiLCJpZCI6Imh0dHA6Ly9leGFtcGxlLmVkdS9jcmVkZW50aWFscy8xODcyIiwiaXNzdWFuY2VEYXRlIjoiMjAxMC0wMS0wMVQxOToyMzoyNFoiLCJpc3N1ZXIiOnsiaWQiOiJkaWQ6ZXhhbXBsZTo3NmUxMmVjNzEyZWJjNmYxYzIyMWViZmViMWYiLCJuYW1lIjoiRXhhbXBsZSBVbml2ZXJzaXR5In0sInJlZmVyZW5jZU51bWJlciI6OC4zMjk0ODQ3ZSswNywidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl19XX19.RlO_1B-7qhQNwo2mmOFUWSa8A6hwaJrtq3q7yJDkKq4k6B-EJ-oyLNM6H_g2_nko2Yg9Im1CiROFm6nK12U_AQ" //nolint:lll

// nolint: gochecknoglobals
var (
	strFilterType = "string"
	arrFilterType = "array"
)

func TestSavePresentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().VDRegistry().Return(nil).AnyTimes()
	provider.EXPECT().VerifiableStore().Return(nil).AnyTimes()
	provider.EXPECT().JSONLDDocumentLoader().Return(nil).AnyTimes()

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
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.PresentationV2{
			Type: presentproof.PresentationMsgTypeV2,
		}))

		err := SavePresentation(provider)(next).Handle(metadata)
		require.EqualError(t, err, "presentations were not provided")
	})

	t.Run("Marshal presentation error", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNamePresentationReceived)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.PresentationV2{
			Type: presentproof.PresentationMsgTypeV2,
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
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.PresentationV2{
			Type: presentproof.PresentationMsgTypeV2,
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
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.PresentationV2{
			Type: presentproof.PresentationMsgTypeV2,
			PresentationsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{Base64: base64.StdEncoding.EncodeToString([]byte(vpJWS))}},
			},
		}))

		verifiableStore := mocksstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SavePresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(errors.New(errMsg))

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		registry := mocksvdr.NewMockRegistry(ctrl)
		registry.EXPECT().Resolve("did:example:ebfeb1f712ebc6f1c276e12ec21").Return(
			&did.DocResolution{DIDDocument: &did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}}}, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRegistry().Return(registry).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore)
		provider.EXPECT().JSONLDDocumentLoader().Return(loader)

		require.EqualError(t, SavePresentation(provider)(next).Handle(metadata), "save presentation: "+errMsg)
	})

	t.Run("No DIDs", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNamePresentationReceived)
		metadata.EXPECT().Properties().Return(map[string]interface{}{})
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.PresentationV2{
			Type: presentproof.PresentationMsgTypeV2,
			PresentationsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{Base64: base64.StdEncoding.EncodeToString([]byte(vpJWS))}},
			},
		}))

		registry := mocksvdr.NewMockRegistry(ctrl)
		registry.EXPECT().Resolve("did:example:ebfeb1f712ebc6f1c276e12ec21").
			Return(&did.DocResolution{DIDDocument: &did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}}}, nil)

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRegistry().Return(registry).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(mocksstore.NewMockStore(ctrl))
		provider.EXPECT().JSONLDDocumentLoader().Return(loader)

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
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.PresentationV2{
			Type: presentproof.PresentationMsgTypeV2,
			PresentationsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{Base64: base64.StdEncoding.EncodeToString([]byte(vpJWSNoID))}},
			},
		}))

		verifiableStore := mocksstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SavePresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)

		registry := mocksvdr.NewMockRegistry(ctrl)
		registry.EXPECT().Resolve("did:example:ebfeb1f712ebc6f1c276e12ec21").Return(
			&did.DocResolution{DIDDocument: &did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}}}, nil)

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRegistry().Return(registry).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore)
		provider.EXPECT().JSONLDDocumentLoader().Return(loader)

		require.NoError(t, SavePresentation(provider)(next).Handle(metadata))
		require.Equal(t, len(props["names"].([]string)), 1)
		require.NotEmpty(t, props["names"].([]string)[0])
	})

	t.Run("Success v2", func(t *testing.T) {
		const vcName = "vc-name"

		props := map[string]interface{}{
			myDIDKey:    myDIDKey,
			theirDIDKey: theirDIDKey,
		}

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNamePresentationReceived)
		metadata.EXPECT().PresentationNames().Return([]string{vcName}).Times(2)
		metadata.EXPECT().Properties().Return(props)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.PresentationV2{
			Type: presentproof.PresentationMsgTypeV2,
			PresentationsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{Base64: base64.StdEncoding.EncodeToString([]byte(vpJWS))}},
			},
		}))

		verifiableStore := mocksstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SavePresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		registry := mocksvdr.NewMockRegistry(ctrl)
		registry.EXPECT().Resolve("did:example:ebfeb1f712ebc6f1c276e12ec21").Return(
			&did.DocResolution{DIDDocument: &did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}}}, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRegistry().Return(registry).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore)
		provider.EXPECT().JSONLDDocumentLoader().Return(loader)

		require.NoError(t, SavePresentation(provider)(next).Handle(metadata))
		require.Equal(t, props["names"], []string{vcName})
	})

	t.Run("Success v3", func(t *testing.T) {
		const vcName = "vc-name"

		props := map[string]interface{}{
			myDIDKey:    myDIDKey,
			theirDIDKey: theirDIDKey,
		}

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNamePresentationReceived)
		metadata.EXPECT().PresentationNames().Return([]string{vcName}).Times(2)
		metadata.EXPECT().Properties().Return(props)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.PresentationV3{
			Type: presentproof.PresentationMsgTypeV3,
			Attachments: []decorator.AttachmentV2{
				{Data: decorator.AttachmentData{Base64: base64.StdEncoding.EncodeToString([]byte(vpJWS))}},
			},
		}))

		verifiableStore := mocksstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SavePresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		registry := mocksvdr.NewMockRegistry(ctrl)
		registry.EXPECT().Resolve("did:example:ebfeb1f712ebc6f1c276e12ec21").Return(
			&did.DocResolution{DIDDocument: &did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}}}, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRegistry().Return(registry).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore)
		provider.EXPECT().JSONLDDocumentLoader().Return(loader)

		require.NoError(t, SavePresentation(provider)(next).Handle(metadata))
		require.Equal(t, props["names"], []string{vcName})
	})
}

func TestPresentationDefinition(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cr, err := tinkcrypto.New()
	require.NoError(t, err)

	km, err := localkms.New("local-lock://custom/master/key/",
		mockkms.NewProviderForKMS(storage.NewMockStoreProvider(), &noop.NoLock{}))
	require.NoError(t, err)

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().VDRegistry().Return(nil).AnyTimes()
	provider.EXPECT().KMS().Return(km).AnyTimes()
	provider.EXPECT().Crypto().Return(cr).AnyTimes()
	provider.EXPECT().JSONLDDocumentLoader().Return(loader).AnyTimes()

	require.NotNil(t, defaultPdOptions().addProof)
	require.NoError(t, defaultPdOptions().addProof(nil))

	next := presentproof.HandlerFunc(func(metadata presentproof.Metadata) error {
		return nil
	})

	t.Run("Ignores processing", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return("state-name")
		require.NoError(t, PresentationDefinition(provider)(next).Handle(metadata))
	})

	t.Run("Ignores processing (no presentation)", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameRequestReceived)
		metadata.EXPECT().Presentation().Return(nil)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.RequestPresentationV2{
			Type: presentproof.RequestPresentationMsgTypeV2,
		}))

		require.Nil(t, PresentationDefinition(provider)(next).Handle(metadata))
	})

	t.Run("Message decode (error)", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameRequestReceived)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(struct {
			Type chan struct{} `json:"@type"`
		}{}))

		require.Error(t, PresentationDefinition(provider)(next).Handle(metadata))
	})

	t.Run("No attachment", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameRequestReceived)
		metadata.EXPECT().Presentation().Return(&presentproof.PresentationV2{}).AnyTimes()
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.RequestPresentationV2{
			Formats: []presentproof.Format{{
				AttachID: uuid.New().String(),
				Format:   peDefinitionFormat,
			}},
			Type: presentproof.RequestPresentationMsgTypeV2,
		}))

		const errMsg = "get attachment by format: not found"
		require.EqualError(t, PresentationDefinition(provider)(next).Handle(metadata), errMsg)
	})

	t.Run("Attachment marshal (error)", func(t *testing.T) {
		ID := uuid.New().String()

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameRequestReceived)
		metadata.EXPECT().Presentation().Return(&presentproof.PresentationV2{}).AnyTimes()
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.RequestPresentationV2{
			Formats: []presentproof.Format{{
				AttachID: ID,
				Format:   peDefinitionFormat,
			}},
			Type: presentproof.RequestPresentationMsgTypeV2,
			RequestPresentationsAttach: []decorator.Attachment{{
				ID: ID,
				Data: decorator.AttachmentData{
					Base64: "ew==",
				},
			}},
		}))

		const errMsg = "unmarshal definition: unexpected end of JSON input"
		require.EqualError(t, PresentationDefinition(provider)(next).Handle(metadata), errMsg)
	})

	t.Run("No credentials", func(t *testing.T) {
		ID := uuid.New().String()

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameRequestReceived)
		metadata.EXPECT().Presentation().Return(&presentproof.PresentationV2{
			PresentationsAttach: []decorator.Attachment{{
				MimeType: mimeTypeApplicationLdJSON,
				Data: decorator.AttachmentData{
					JSON: &verifiable.Credential{
						ID:      uuid.New().URN(),
						Context: []string{verifiable.ContextURI},
						Types:   []string{verifiable.VCType},
						Subject: verifiable.Subject{},
						Issuer:  verifiable.Issuer{ID: uuid.New().URN()},
						Issued:  util.NewTime(time.Now()),
						CustomFields: map[string]interface{}{
							"first_name": "Jesse",
						},
					},
				},
			}},
		}).AnyTimes()
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.RequestPresentationV2{
			Formats: []presentproof.Format{{
				AttachID: ID,
				Format:   peDefinitionFormat,
			}},
			Type: presentproof.RequestPresentationMsgTypeV2,
			RequestPresentationsAttach: []decorator.Attachment{{
				ID: ID,
				Data: decorator.AttachmentData{
					JSON: map[string]interface{}{
						"presentation_definition": &presexch.PresentationDefinition{
							ID: uuid.New().String(),
							InputDescriptors: []*presexch.InputDescriptor{{
								Schema: []*presexch.Schema{{
									URI: verifiable.ContextURI,
								}},
								ID: uuid.New().String(),
								Constraints: &presexch.Constraints{
									Fields: []*presexch.Field{{
										Path:   []string{"$.credentialSubject.givenName", "$.credentialSubject.familyName"},
										Filter: &presexch.Filter{Type: &strFilterType},
									}, {
										Path:   []string{"$.credentialSubject.type"},
										Filter: &presexch.Filter{Type: &arrFilterType},
									}},
								},
							}},
						},
					},
				},
			}},
		}))

		const errMsg = "create VP: credentials do not satisfy requirements"
		require.EqualError(t, PresentationDefinition(provider)(next).Handle(metadata), errMsg)
	})
	t.Run("Sign error", func(t *testing.T) {
		ID := uuid.New().String()

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameRequestReceived)
		metadata.EXPECT().GetAddProofFn().Return(func(presentation *verifiable.Presentation) error {
			return errors.New("test")
		})
		metadata.EXPECT().Presentation().Return(&presentproof.PresentationV2{
			PresentationsAttach: []decorator.Attachment{{
				MimeType: mimeTypeApplicationLdJSON,
				Data: decorator.AttachmentData{
					JSON: &verifiable.Credential{
						ID:      "http://example.edu/credentials/1872",
						Context: []string{verifiable.ContextURI},
						Types:   []string{verifiable.VCType},
						Subject: "did:example:76e12ec712ebc6f1c221ebfeb1f",
						Issued: &util.TimeWrapper{
							Time: time.Now(),
						},
						Issuer: verifiable.Issuer{
							ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
						},
						CustomFields: map[string]interface{}{
							"first_name": "First name",
							"last_name":  "Last name",
							"info":       "Info",
						},
					},
				},
			}, {
				MimeType: "application/json",
				Data: decorator.AttachmentData{
					JSON: map[string]struct{}{},
				},
			}},
		}).AnyTimes()
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.RequestPresentationV2{
			Formats: []presentproof.Format{{
				AttachID: ID,
				Format:   peDefinitionFormat,
			}},
			Type: presentproof.RequestPresentationMsgTypeV2,
			RequestPresentationsAttach: []decorator.Attachment{{
				ID: ID,
				Data: decorator.AttachmentData{
					JSON: map[string]interface{}{
						"presentation_definition": &presexch.PresentationDefinition{
							ID: uuid.New().String(),
							InputDescriptors: []*presexch.InputDescriptor{{
								ID: uuid.New().String(),
								Schema: []*presexch.Schema{{
									URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
								}},
								Constraints: &presexch.Constraints{
									Fields: []*presexch.Field{{
										Path:   []string{"$.first_name"},
										Filter: &presexch.Filter{Type: &strFilterType},
									}, {
										Path:   []string{"$.last_name"},
										Filter: &presexch.Filter{Type: &strFilterType},
									}},
								},
							}},
						},
					},
				},
			}},
		}))

		require.EqualError(t, PresentationDefinition(provider)(next).Handle(metadata), "add proof: test")
	})

	t.Run("Success v2", func(t *testing.T) {
		ID := uuid.New().String()

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameRequestReceived)
		metadata.EXPECT().GetAddProofFn().Return(nil)
		metadata.EXPECT().Presentation().Return(&presentproof.PresentationV2{
			PresentationsAttach: []decorator.Attachment{{
				MimeType: mimeTypeApplicationLdJSON,
				Data: decorator.AttachmentData{
					JSON: &verifiable.Credential{
						ID:      "http://example.edu/credentials/1872",
						Context: []string{verifiable.ContextURI},
						Types:   []string{verifiable.VCType},
						Subject: "did:example:76e12ec712ebc6f1c221ebfeb1f",
						Issued: &util.TimeWrapper{
							Time: time.Now(),
						},
						Issuer: verifiable.Issuer{
							ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
						},
						CustomFields: map[string]interface{}{
							"first_name": "First name",
							"last_name":  "Last name",
							"info":       "Info",
						},
					},
				},
			}, {
				MimeType: "application/json",
				Data: decorator.AttachmentData{
					JSON: map[string]struct{}{},
				},
			}},
		}).AnyTimes()
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.RequestPresentationV2{
			Formats: []presentproof.Format{{
				AttachID: ID,
				Format:   peDefinitionFormat,
			}},
			Type: presentproof.RequestPresentationMsgTypeV2,
			RequestPresentationsAttach: []decorator.Attachment{{
				ID: ID,
				Data: decorator.AttachmentData{
					JSON: map[string]interface{}{
						"presentation_definition": &presexch.PresentationDefinition{
							ID: uuid.New().String(),
							InputDescriptors: []*presexch.InputDescriptor{{
								ID: uuid.New().String(),
								Schema: []*presexch.Schema{{
									URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
								}},
								Constraints: &presexch.Constraints{
									Fields: []*presexch.Field{{
										Path:   []string{"$.first_name"},
										Filter: &presexch.Filter{Type: &strFilterType},
									}, {
										Path:   []string{"$.last_name"},
										Filter: &presexch.Filter{Type: &strFilterType},
									}},
								},
							}},
						},
					},
				},
			}},
		}))

		require.Nil(t, PresentationDefinition(provider, WithAddProofFn(AddBBSProofFn(provider)))(next).Handle(metadata))
	})

	t.Run("Success v3", func(t *testing.T) {
		ID := uuid.New().String()

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameRequestReceived)
		metadata.EXPECT().GetAddProofFn().Return(nil)
		metadata.EXPECT().PresentationV3().Return(&presentproof.PresentationV3{
			Attachments: []decorator.AttachmentV2{{
				MediaType: mimeTypeApplicationLdJSON,
				Data: decorator.AttachmentData{
					JSON: &verifiable.Credential{
						ID:      "http://example.edu/credentials/1872",
						Context: []string{verifiable.ContextURI},
						Types:   []string{verifiable.VCType},
						Subject: "did:example:76e12ec712ebc6f1c221ebfeb1f",
						Issued: &util.TimeWrapper{
							Time: time.Now(),
						},
						Issuer: verifiable.Issuer{
							ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
						},
						CustomFields: map[string]interface{}{
							"first_name": "First name",
							"last_name":  "Last name",
							"info":       "Info",
						},
					},
				},
			}, {
				MediaType: "application/json",
				Data: decorator.AttachmentData{
					JSON: map[string]struct{}{},
				},
			}},
		}).AnyTimes()
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(presentproof.RequestPresentationV3{
			Type: presentproof.RequestPresentationMsgTypeV3,
			Attachments: []decorator.AttachmentV2{{
				ID:     ID,
				Format: peDefinitionFormat,
				Data: decorator.AttachmentData{
					JSON: map[string]interface{}{
						"presentation_definition": &presexch.PresentationDefinition{
							ID: uuid.New().String(),
							InputDescriptors: []*presexch.InputDescriptor{{
								ID: uuid.New().String(),
								Schema: []*presexch.Schema{{
									URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
								}},
								Constraints: &presexch.Constraints{
									Fields: []*presexch.Field{{
										Path:   []string{"$.first_name"},
										Filter: &presexch.Filter{Type: &strFilterType},
									}, {
										Path:   []string{"$.last_name"},
										Filter: &presexch.Filter{Type: &strFilterType},
									}},
								},
							}},
						},
					},
				},
			}},
		}))

		require.Nil(t, PresentationDefinition(provider, WithAddProofFn(AddBBSProofFn(provider)))(next).Handle(metadata))
	})
}
