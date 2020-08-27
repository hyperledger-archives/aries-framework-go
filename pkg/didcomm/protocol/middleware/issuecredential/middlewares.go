/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	storeverifiable "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
)

const (
	stateNameCredentialReceived = "credential-received"
	myDIDKey                    = "myDID"
	theirDIDKey                 = "theirDID"
	namesKey                    = "names"
)

// Metadata is an alias to the original Metadata.
type Metadata issuecredential.Metadata

// Provider contains dependencies for the SaveCredentials middleware function.
type Provider interface {
	VerifiableStore() storeverifiable.Store
	VDRIRegistry() vdri.Registry
}

// SaveCredentials the helper function for the issue credential protocol which saves credentials.
func SaveCredentials(p Provider) issuecredential.Middleware {
	registryVDRI := p.VDRIRegistry()
	store := p.VerifiableStore()

	return func(next issuecredential.Handler) issuecredential.Handler {
		return issuecredential.HandlerFunc(func(metadata issuecredential.Metadata) error {
			if metadata.StateName() != stateNameCredentialReceived {
				return next.Handle(metadata)
			}

			var credential = issuecredential.IssueCredential{}

			err := metadata.Message().Decode(&credential)
			if err != nil {
				return fmt.Errorf("decode: %w", err)
			}

			credentials, err := toVerifiableCredentials(registryVDRI, credential.CredentialsAttach)
			if err != nil {
				return fmt.Errorf("to verifiable credentials: %w", err)
			}

			if len(credentials) == 0 {
				return errors.New("credentials were not provided")
			}

			var names []string
			var properties = metadata.Properties()

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

func getName(idx int, id string, metadata issuecredential.Metadata) string {
	var name = id
	if len(metadata.CredentialNames()) > idx {
		name = metadata.CredentialNames()[idx]
	}

	if name != "" {
		return name
	}

	return uuid.New().String()
}

func toVerifiableCredentials(vReg vdri.Registry, attachments []decorator.Attachment) ([]*verifiable.Credential, error) {
	var credentials []*verifiable.Credential

	for i := range attachments {
		rawVC, err := attachments[i].Data.Fetch()
		if err != nil {
			return nil, fmt.Errorf("fetch: %w", err)
		}

		vc, err := verifiable.ParseCredential(rawVC, verifiable.WithPublicKeyFetcher(
			verifiable.NewDIDKeyResolver(vReg).PublicKeyFetcher(),
		))
		if err != nil {
			return nil, fmt.Errorf("new credential: %w", err)
		}

		credentials = append(credentials, vc)
	}

	return credentials, nil
}
