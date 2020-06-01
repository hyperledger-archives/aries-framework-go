/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	storeverifiable "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
)

const stateNamePresentationReceived = "presentation-received"

// Metadata is an alias to the original Metadata
type Metadata presentproof.Metadata

// Provider contains dependencies for the SavePresentation middleware function
type Provider interface {
	VerifiableStore() storeverifiable.Store
	VDRIRegistry() vdri.Registry
}

// SavePresentation the helper function for the present proof protocol which saves the presentations
func SavePresentation(p Provider) presentproof.Middleware {
	registryVDRI := p.VDRIRegistry()
	store := p.VerifiableStore()

	return func(next presentproof.Handler) presentproof.Handler {
		return presentproof.HandlerFunc(func(metadata presentproof.Metadata) error {
			if metadata.StateName() != stateNamePresentationReceived {
				return next.Handle(metadata)
			}

			var presentation = presentproof.Presentation{}
			if err := metadata.Message().Decode(&presentation); err != nil {
				return fmt.Errorf("decode: %w", err)
			}

			presentations, err := toVerifiablePresentation(registryVDRI, presentation.Presentations)
			if err != nil {
				return fmt.Errorf("to verifiable presentation: %w", err)
			}

			if len(presentations) == 0 {
				return errors.New("presentations were not provided")
			}

			for i, presentation := range presentations {
				var name = presentation.ID
				if len(metadata.PresentationNames()) > i {
					name = metadata.PresentationNames()[i]
				}

				if err := store.SavePresentation(name, presentation); err != nil {
					return fmt.Errorf("save presentation: %w", err)
				}
			}

			return next.Handle(metadata)
		})
	}
}

func toVerifiablePresentation(registry vdri.Registry, data []decorator.Attachment) ([]*verifiable.Presentation, error) {
	var presentations []*verifiable.Presentation

	for i := range data {
		raw, err := data[i].Data.Fetch()
		if err != nil {
			return nil, fmt.Errorf("fetch: %w", err)
		}

		presentation, err := verifiable.ParsePresentation(raw, verifiable.WithPresPublicKeyFetcher(
			verifiable.NewDIDKeyResolver(registry).PublicKeyFetcher(),
		))

		if err != nil {
			return nil, fmt.Errorf("parse presentation: %w", err)
		}

		presentations = append(presentations, presentation)
	}

	return presentations, nil
}
