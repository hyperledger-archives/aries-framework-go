/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/protocol/middleware/issuecredential"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/framework/aries/api/vdr"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/store/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
)

func getCredential() *verifiable.Credential {
	return &verifiable.Credential{
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
		Issued:  util.NewTime(time.Date(2010, time.January, 1, 19, 23, 24, 0, time.UTC)),
		Schemas: []verifiable.TypedID{},
		CustomFields: map[string]interface{}{
			"referenceNumber": 83294847,
		},
	}
}

func TestSaveCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().VDRegistry().Return(nil).AnyTimes()
	provider.EXPECT().VerifiableStore().Return(nil).AnyTimes()
	provider.EXPECT().JSONLDDocumentLoader().Return(nil).AnyTimes()

	next := issuecredential.HandlerFunc(func(metadata issuecredential.Metadata) error {
		return nil
	})

	t.Run("Ignores processing", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return("state-name")
		require.NoError(t, SaveCredentials(provider)(next).Handle(metadata))
	})

	t.Run("Credentials not provided", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredentialV2{
			Type: issuecredential.IssueCredentialMsgTypeV2,
		}))
		metadata.EXPECT().Properties().Return(map[string]interface{}{
			myDIDKey:    myDIDKey,
			theirDIDKey: theirDIDKey,
		})

		err := SaveCredentials(provider)(next).Handle(metadata)
		require.EqualError(t, err, "credentials were not provided")
	})

	t.Run("Marshal credentials error", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredentialV2{
			Type: issuecredential.IssueCredentialMsgTypeV2,
			CredentialsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: struct{ C chan int }{}}},
			},
		}))
		metadata.EXPECT().Properties().Return(map[string]interface{}{
			myDIDKey:    myDIDKey,
			theirDIDKey: theirDIDKey,
		})

		err := SaveCredentials(provider)(next).Handle(metadata)
		require.Contains(t, fmt.Sprintf("%v", err), "json: unsupported type")
	})

	t.Run("Decode error", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().Message().Return(service.DIDCommMsgMap{"@type": map[int]int{}})
		metadata.EXPECT().Properties().Return(map[string]interface{}{
			myDIDKey:    myDIDKey,
			theirDIDKey: theirDIDKey,
		})

		err := SaveCredentials(provider)(next).Handle(metadata)
		require.Contains(t, fmt.Sprintf("%v", err), "got unconvertible type")
	})

	t.Run("Invalid credentials", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredentialV2{
			Type: issuecredential.IssueCredentialMsgTypeV2,
			CredentialsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: &verifiable.Credential{
					Context: []string{"https://www.w3.org/2018/credentials/v1"},
				}}},
			},
		}))
		metadata.EXPECT().Properties().Return(map[string]interface{}{
			myDIDKey:    myDIDKey,
			theirDIDKey: theirDIDKey,
		})

		err := SaveCredentials(provider)(next).Handle(metadata)
		require.Contains(t, fmt.Sprintf("%v", err), "to verifiable credentials")
	})

	t.Run("DB error", func(t *testing.T) {
		const (
			vcName = "vc-name"
			errMsg = "error message"
		)

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().CredentialNames().Return([]string{vcName}).Times(2)
		metadata.EXPECT().Properties().Return(map[string]interface{}{
			myDIDKey:    myDIDKey,
			theirDIDKey: theirDIDKey,
		})
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredentialV2{
			Type: issuecredential.IssueCredentialMsgTypeV2,
			CredentialsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: getCredential()}},
			},
		}))

		verifiableStore := mockstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SaveCredential(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(errors.New(errMsg))

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		p := mocks.NewMockProvider(ctrl)
		p.EXPECT().VDRegistry().Return(nil).AnyTimes()
		p.EXPECT().VerifiableStore().Return(verifiableStore)
		p.EXPECT().JSONLDDocumentLoader().Return(loader)

		require.EqualError(t, SaveCredentials(p)(next).Handle(metadata), "save credential: "+errMsg)
	})

	t.Run("No DIDs", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().Properties().Return(map[string]interface{}{})
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredentialV2{
			Type: issuecredential.IssueCredentialMsgTypeV2,
			CredentialsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: getCredential()}},
			},
		}))

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		p := mocks.NewMockProvider(ctrl)
		p.EXPECT().VDRegistry().Return(nil).AnyTimes()
		p.EXPECT().VerifiableStore().Return(mockstore.NewMockStore(ctrl))
		p.EXPECT().JSONLDDocumentLoader().Return(loader)

		require.EqualError(t, SaveCredentials(p)(next).Handle(metadata), "myDID or theirDID is absent")
	})

	t.Run("Success", func(t *testing.T) {
		const vcName = "vc-name"

		props := map[string]interface{}{
			myDIDKey:    myDIDKey,
			theirDIDKey: theirDIDKey,
		}

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().CredentialNames().Return([]string{vcName}).Times(2)
		metadata.EXPECT().Properties().Return(props)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredentialV2{
			Type: issuecredential.IssueCredentialMsgTypeV2,
			CredentialsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: getCredential()}},
			},
		}))

		verifiableStore := mockstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SaveCredential(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		p := mocks.NewMockProvider(ctrl)
		p.EXPECT().VDRegistry().Return(nil).AnyTimes()
		p.EXPECT().VerifiableStore().Return(verifiableStore)
		p.EXPECT().JSONLDDocumentLoader().Return(loader)

		require.NoError(t, SaveCredentials(p)(next).Handle(metadata))
		require.Equal(t, props["names"], []string{vcName})
	})

	t.Run("Success - no save", func(t *testing.T) {
		props := map[string]interface{}{
			myDIDKey:              myDIDKey,
			theirDIDKey:           theirDIDKey,
			SkipCredentialSaveKey: true,
		}

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().Properties().Return(props)

		require.NoError(t, SaveCredentials(provider)(next).Handle(metadata))
	})

	t.Run("Success V3", func(t *testing.T) {
		const vcName = "vc-name"

		props := map[string]interface{}{
			myDIDKey:    myDIDKey,
			theirDIDKey: theirDIDKey,
		}

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().CredentialNames().Return([]string{vcName}).Times(2)
		metadata.EXPECT().Properties().Return(props)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredentialV3{
			Type: issuecredential.IssueCredentialMsgTypeV3,
			Attachments: []decorator.AttachmentV2{
				{Data: decorator.AttachmentData{JSON: getCredential()}},
			},
		}))

		verifiableStore := mockstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SaveCredential(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRegistry().Return(nil).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore)
		provider.EXPECT().JSONLDDocumentLoader().Return(loader)

		require.NoError(t, SaveCredentials(provider)(next).Handle(metadata))
		require.Equal(t, props["names"], []string{vcName})
	})

	t.Run("Success (no ID)", func(t *testing.T) {
		props := map[string]interface{}{
			myDIDKey:    myDIDKey,
			theirDIDKey: theirDIDKey,
		}

		cred := getCredential()
		cred.ID = ""

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().CredentialNames().Return([]string{})
		metadata.EXPECT().Properties().Return(props)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredentialV2{
			Type: issuecredential.IssueCredentialMsgTypeV2,
			CredentialsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: cred}},
			},
		}))

		verifiableStore := mockstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SaveCredential(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRegistry().Return(nil).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore)
		provider.EXPECT().JSONLDDocumentLoader().Return(loader)

		require.NoError(t, SaveCredentials(provider)(next).Handle(metadata))
		require.Equal(t, len(props["names"].([]string)), 1)
		require.NotEmpty(t, props["names"].([]string)[0])
	})

	t.Run("Success (credential with a proof)", func(t *testing.T) {
		const vcName = "vc-name"

		var credential map[string]interface{}
		// nolint: lll
		require.NoError(t, json.Unmarshal([]byte(`{
				"@context": [
					"https://www.w3.org/2018/credentials/v1",
					"https://www.w3.org/2018/credentials/examples/v1"
				],
				"credentialSubject": {
					"degree": {
						"type": "BachelorDegree",
						"university": "MIT"
					},
					"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
					"name": "Jayden Doe",
					"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
				},
				"expirationDate": "2020-01-01T19:23:24Z",
				"id": "http://example.edu/credentials/1872",
				"issuanceDate": "2009-01-01T19:23:24Z",
				"issuer": {
					"id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
					"name": "Example University"
				},
				"proof": {
					"created": "2010-01-01T19:23:24Z",
					"jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..lrkhpRH4tWl6KzQKHlcyAwSm8qUTXIMSKmD3QASF_uI5QW8NWLxLebXmnQpIM8H7umhLA6dINSYVowcaPdpwBw",
					"proofPurpose": "assertionMethod",
					"type": "Ed25519Signature2018",
					"verificationMethod": "did:example:123456#key1"
				},
				"referenceNumber": 83294849,
				"type": [
					"VerifiableCredential",
					"UniversityDegreeCredential"
				]
			}`), &credential))

		props := map[string]interface{}{
			myDIDKey:    myDIDKey,
			theirDIDKey: theirDIDKey,
		}

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().CredentialNames().Return([]string{vcName}).Times(2)
		metadata.EXPECT().Properties().Return(props)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredentialV2{
			Type: issuecredential.IssueCredentialMsgTypeV2,
			CredentialsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: credential}},
			},
		}))

		verifiableStore := mockstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SaveCredential(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		registry := mockvdr.NewMockRegistry(ctrl)
		registry.EXPECT().Resolve("did:example:123456").Return(&did.DocResolution{DIDDocument: &did.Doc{
			VerificationMethod: []did.VerificationMethod{{
				ID: "#key1",
				Value: []byte{
					234, 100, 192, 93, 251, 181, 198, 73, 122, 220, 27, 48, 93, 73, 166,
					33, 152, 140, 168, 36, 9, 205, 59, 161, 137, 7, 164, 9, 176, 252, 1, 171,
				},
			}},
		}}, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRegistry().Return(registry).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore)
		provider.EXPECT().JSONLDDocumentLoader().Return(loader)

		require.NoError(t, SaveCredentials(provider)(next).Handle(metadata))
		require.Equal(t, props["names"], []string{vcName})
	})
}
