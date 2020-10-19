/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	storeverifiable "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
)

const (
	stateNamePresentationReceived = "presentation-received"
	myDIDKey                      = "myDID"
	theirDIDKey                   = "theirDID"
	namesKey                      = "names"
)

// Metadata is an alias to the original Metadata.
type Metadata presentproof.Metadata

// Provider contains dependencies for the SavePresentation middleware function.
type Provider interface {
	VerifiableStore() storeverifiable.Store
	VDRegistry() vdrapi.Registry
}

// SavePresentation the helper function for the present proof protocol which saves the presentations.
func SavePresentation(p Provider) presentproof.Middleware {
	vdr := p.VDRegistry()
	store := p.VerifiableStore()

	return func(next presentproof.Handler) presentproof.Handler {
		return presentproof.HandlerFunc(func(metadata presentproof.Metadata) error {
			if metadata.StateName() != stateNamePresentationReceived {
				return next.Handle(metadata)
			}

			presentation := presentproof.Presentation{}
			if err := metadata.Message().Decode(&presentation); err != nil {
				return fmt.Errorf("decode: %w", err)
			}

			presentations, err := toVerifiablePresentation(vdr, presentation.PresentationsAttach)
			if err != nil {
				return fmt.Errorf("to verifiable presentation: %w", err)
			}

			if len(presentations) == 0 {
				return errors.New("presentations were not provided")
			}

			var names []string
			properties := metadata.Properties()

			// nolint: errcheck
			myDID, _ := properties[myDIDKey].(string)
			// nolint: errcheck
			theirDID, _ := properties[theirDIDKey].(string)
			if myDID == "" || theirDID == "" {
				return errors.New("myDID or theirDID is absent")
			}

			for i, presentation := range presentations {
				names = append(names, getName(i, presentation.ID, metadata))

				err := store.SavePresentation(names[i], presentation,
					storeverifiable.WithMyDID(myDID),
					storeverifiable.WithTheirDID(theirDID),
				)
				if err != nil {
					return fmt.Errorf("save presentation: %w", err)
				}
			}

			properties[namesKey] = names

			return next.Handle(metadata)
		})
	}
}

func getName(idx int, id string, metadata presentproof.Metadata) string {
	name := id
	if len(metadata.PresentationNames()) > idx {
		name = metadata.PresentationNames()[idx]
	}

	if name != "" {
		return name
	}

	return uuid.New().String()
}

func toVerifiablePresentation(vdr vdrapi.Registry, data []decorator.Attachment) ([]*verifiable.Presentation, error) {
	var presentations []*verifiable.Presentation

	for i := range data {
		raw, err := data[i].Data.Fetch()
		if err != nil {
			return nil, fmt.Errorf("fetch: %w", err)
		}

		presentation, err := verifiable.ParsePresentation(raw, verifiable.WithPresPublicKeyFetcher(
			verifiable.NewDIDKeyResolver(vdr).PublicKeyFetcher(),
		))
		if err != nil {
			return nil, fmt.Errorf("parse presentation: %w", err)
		}

		presentations = append(presentations, presentation)
	}

	return presentations, nil
}
