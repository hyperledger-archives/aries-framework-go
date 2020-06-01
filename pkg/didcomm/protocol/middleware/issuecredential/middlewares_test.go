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
	mocksvdri "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/framework/aries/api/vdri"
	mocksstore "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/store/verifiable"
)

func TestSaveCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	provider := mocks.NewMockProvider(ctrl)
	provider.EXPECT().VDRIRegistry().Return(nil).AnyTimes()
	provider.EXPECT().VerifiableStore().Return(nil).AnyTimes()

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
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredential{
			Type: issuecredential.IssueCredentialMsgType,
		}))

		err := SaveCredentials(provider)(next).Handle(metadata)
		require.EqualError(t, err, "credentials were not provided")
	})

	t.Run("Marshal credentials error", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredential{
			Type: issuecredential.IssueCredentialMsgType,
			CredentialsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: struct{ C chan int }{}}},
			},
		}))

		err := SaveCredentials(provider)(next).Handle(metadata)
		require.Contains(t, fmt.Sprintf("%v", err), "json: unsupported type")
	})

	t.Run("Decode error", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().Message().Return(service.DIDCommMsgMap{"@type": map[int]int{}})

		err := SaveCredentials(provider)(next).Handle(metadata)
		require.Contains(t, fmt.Sprintf("%v", err), "got unconvertible type")
	})

	t.Run("Invalid credentials", func(t *testing.T) {
		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredential{
			Type: issuecredential.IssueCredentialMsgType,
			CredentialsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: &verifiable.Credential{
					Context: []string{"https://www.w3.org/2018/credentials/v1"},
				}}},
			},
		}))

		err := SaveCredentials(provider)(next).Handle(metadata)
		require.Contains(t, fmt.Sprintf("%v", err), "to verifiable credentials")
	})

	t.Run("DB error", func(t *testing.T) {
		const (
			vcName = "vc-name"
			errMsg = "error message"
		)

		var issued = time.Date(2010, time.January, 1, 19, 23, 24, 0, time.UTC)

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().CredentialNames().Return([]string{vcName}).Times(2)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredential{
			Type: issuecredential.IssueCredentialMsgType,
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
		}))

		verifiableStore := mocksstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SaveCredential(gomock.Any(), gomock.Any()).Return(errors.New(errMsg))

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRIRegistry().Return(nil).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore)

		require.EqualError(t, SaveCredentials(provider)(next).Handle(metadata), "save credential: "+errMsg)
	})

	t.Run("Success", func(t *testing.T) {
		const vcName = "vc-name"
		var issued = time.Date(2010, time.January, 1, 19, 23, 24, 0, time.UTC)

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().CredentialNames().Return([]string{vcName}).Times(2)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredential{
			Type: issuecredential.IssueCredentialMsgType,
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
		}))

		verifiableStore := mocksstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SaveCredential(gomock.Any(), gomock.Any()).Return(nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRIRegistry().Return(nil).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore)

		require.NoError(t, SaveCredentials(provider)(next).Handle(metadata))
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

		metadata := mocks.NewMockMetadata(ctrl)
		metadata.EXPECT().StateName().Return(stateNameCredentialReceived)
		metadata.EXPECT().CredentialNames().Return([]string{vcName}).Times(2)
		metadata.EXPECT().Message().Return(service.NewDIDCommMsgMap(issuecredential.IssueCredential{
			Type: issuecredential.IssueCredentialMsgType,
			CredentialsAttach: []decorator.Attachment{
				{Data: decorator.AttachmentData{JSON: credential}},
			},
		}))

		verifiableStore := mocksstore.NewMockStore(ctrl)
		verifiableStore.EXPECT().SaveCredential(gomock.Any(), gomock.Any()).Return(nil)

		registry := mocksvdri.NewMockRegistry(ctrl)
		registry.EXPECT().Resolve("did:example:123456").Return(&did.Doc{
			PublicKey: []did.PublicKey{{
				ID: "#key1",
				Value: []byte{
					234, 100, 192, 93, 251, 181, 198, 73, 122, 220, 27, 48, 93, 73, 166,
					33, 152, 140, 168, 36, 9, 205, 59, 161, 137, 7, 164, 9, 176, 252, 1, 171,
				},
			}},
		}, nil)

		provider := mocks.NewMockProvider(ctrl)
		provider.EXPECT().VDRIRegistry().Return(registry).AnyTimes()
		provider.EXPECT().VerifiableStore().Return(verifiableStore)

		require.NoError(t, SaveCredentials(provider)(next).Handle(metadata))
	})
}
