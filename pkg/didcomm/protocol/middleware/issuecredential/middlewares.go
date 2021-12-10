/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	storeverifiable "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
)

const (
	// SkipCredentialSaveKey is present in metadata properties as `true` then accepted credential will not be saved in
	// verifiable store by middleware.
	SkipCredentialSaveKey = "skip-credential-save"

	stateNameCredentialReceived = "credential-received"
	myDIDKey                    = "myDID"
	theirDIDKey                 = "theirDID"
	namesKey                    = "names"
	mimeTypeAll                 = "*"
)

// Metadata is an alias to the original Metadata.
type Metadata issuecredential.Metadata

// Provider contains dependencies for the SaveCredentials middleware function.
type Provider interface {
	VerifiableStore() storeverifiable.Store
	VDRegistry() vdrapi.Registry
	JSONLDDocumentLoader() ld.DocumentLoader
}

// SaveCredentials the helper function for the issue credential protocol which saves credentials.
func SaveCredentials(p Provider) issuecredential.Middleware { //nolint: funlen,gocognit,gocyclo
	vdr := p.VDRegistry()
	store := p.VerifiableStore()
	documentLoader := p.JSONLDDocumentLoader()

	return func(next issuecredential.Handler) issuecredential.Handler {
		return issuecredential.HandlerFunc(func(metadata issuecredential.Metadata) error {
			if metadata.StateName() != stateNameCredentialReceived {
				return next.Handle(metadata)
			}

			properties := metadata.Properties()

			// skip storage if SkipCredentialSaveKey is enabled
			if val, ok := properties[SkipCredentialSaveKey]; ok {
				if skip, ok := val.(bool); ok && skip {
					return next.Handle(metadata)
				}
			}

			msg := metadata.Message()

			attachments, err := getAttachments(msg)
			if err != nil {
				return fmt.Errorf("get attachments: %w", err)
			}

			credentials, err := toVerifiableCredentials(vdr, attachments, documentLoader)
			if err != nil {
				return fmt.Errorf("to verifiable credentials: %w", err)
			}

			if len(credentials) == 0 {
				return errors.New("credentials were not provided")
			}

			var names []string

			// nolint: errcheck
			myDID, _ := properties[myDIDKey].(string)
			// nolint: errcheck
			theirDID, _ := properties[theirDIDKey].(string)
			if myDID == "" || theirDID == "" {
				return errors.New("myDID or theirDID is absent")
			}

			for i, credential := range credentials {
				names = append(names, getName(i, credential.ID, metadata))

				err := store.SaveCredential(names[i], credential,
					storeverifiable.WithMyDID(myDID),
					storeverifiable.WithTheirDID(theirDID),
				)
				if err != nil {
					return fmt.Errorf("save credential: %w", err)
				}
			}

			properties[namesKey] = names

			return next.Handle(metadata)
		})
	}
}

func getAttachments(msg service.DIDCommMsg) ([]decorator.AttachmentData, error) {
	if strings.HasPrefix(msg.Type(), issuecredential.SpecV3) {
		cred := issuecredential.IssueCredentialV3{}
		if err := msg.Decode(&cred); err != nil {
			return nil, fmt.Errorf("decode: %w", err)
		}

		return filterByMediaType(cred.Attachments, mimeTypeAll), nil
	}

	cred := issuecredential.IssueCredentialV2{}
	if err := msg.Decode(&cred); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	return filterByMimeType(cred.CredentialsAttach, mimeTypeAll), nil
}

func getName(idx int, id string, metadata issuecredential.Metadata) string {
	name := id
	if len(metadata.CredentialNames()) > idx {
		name = metadata.CredentialNames()[idx]
	}

	if name != "" {
		return name
	}

	return uuid.New().String()
}

func toVerifiableCredentials(v vdrapi.Registry, attachments []decorator.AttachmentData,
	documentLoader ld.DocumentLoader) ([]*verifiable.Credential, error) {
	var credentials []*verifiable.Credential

	for i := range attachments {
		rawVC, err := attachments[i].Fetch()
		if err != nil {
			return nil, fmt.Errorf("fetch: %w", err)
		}

		vc, err := verifiable.ParseCredential(rawVC,
			verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(v).PublicKeyFetcher()),
			verifiable.WithJSONLDDocumentLoader(documentLoader))
		if err != nil {
			return nil, fmt.Errorf("new credential: %w", err)
		}

		credentials = append(credentials, vc)
	}

	return credentials, nil
}

func filterByMimeType(attachments []decorator.Attachment, mimeType string) []decorator.AttachmentData {
	var result []decorator.AttachmentData

	for i := range attachments {
		if attachments[i].MimeType != mimeType && mimeType != mimeTypeAll {
			continue
		}

		result = append(result, attachments[i].Data)
	}

	return result
}

func filterByMediaType(attachments []decorator.AttachmentV2, mediaType string) []decorator.AttachmentData {
	var result []decorator.AttachmentData

	for i := range attachments {
		if attachments[i].MediaType != mediaType && mediaType != mimeTypeAll {
			continue
		}

		result = append(result, attachments[i].Data)
	}

	return result
}
