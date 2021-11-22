/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packager"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/anoncrypt"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/authcrypt"
	legacy "github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/legacy/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/messagepickup"
	mdissuecredential "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/middleware/issuecredential"
	mdpresentproof "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/middleware/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// defFrameworkOpts provides default framework options.
func defFrameworkOpts(frameworkOpts *Aries) error { //nolint:gocyclo
	// TODO https://github.com/hyperledger/aries-framework-go/issues/209 Move default providers to the sub-package
	if len(frameworkOpts.outboundTransports) == 0 {
		outbound, err := arieshttp.NewOutbound(arieshttp.WithOutboundHTTPClient(&http.Client{}))
		if err != nil {
			return fmt.Errorf("http outbound transport initialization failed: %w", err)
		}

		frameworkOpts.outboundTransports = append(frameworkOpts.outboundTransports, outbound)
	}

	if frameworkOpts.storeProvider == nil {
		frameworkOpts.storeProvider = storeProvider()
	}

	err := createJSONLDContextStore(frameworkOpts)
	if err != nil {
		return err
	}

	err = createJSONLDRemoteProviderStore(frameworkOpts)
	if err != nil {
		return err
	}

	err = createJSONLDDocumentLoader(frameworkOpts)
	if err != nil {
		return err
	}

	err = assignVerifiableStoreIfNeeded(frameworkOpts, frameworkOpts.storeProvider)
	if err != nil {
		return err
	}

	// order is important:
	// - Route depends on MessagePickup
	// - DIDExchange depends on Route
	// - OutOfBand depends on DIDExchange
	// - Introduce depends on OutOfBand
	frameworkOpts.protocolSvcCreators = append(frameworkOpts.protocolSvcCreators,
		newMessagePickupSvc(), newRouteSvc(), newExchangeSvc(), newOutOfBandSvc(),
		newIntroduceSvc(), newIssueCredentialSvc(), newPresentProofSvc(), newOutOfBandV2Svc())

	if frameworkOpts.secretLock == nil && frameworkOpts.kmsCreator == nil {
		err = createDefSecretLock(frameworkOpts)
		if err != nil {
			return err
		}
	}

	return setAdditionalDefaultOpts(frameworkOpts)
}

func newExchangeSvc() api.ProtocolSvcCreator {
	return api.ProtocolSvcCreator{
		Create: func(prv api.Provider) (dispatcher.ProtocolService, error) {
			return &didexchange.Service{}, nil
		},
	}
}

func newIntroduceSvc() api.ProtocolSvcCreator {
	return api.ProtocolSvcCreator{
		Create: func(prv api.Provider) (dispatcher.ProtocolService, error) {
			return &introduce.Service{}, nil
		},
	}
}

func newIssueCredentialSvc() api.ProtocolSvcCreator {
	return api.ProtocolSvcCreator{
		Create: func(prv api.Provider) (dispatcher.ProtocolService, error) {
			return &issuecredential.Service{}, nil
		},
		Init: func(svc dispatcher.ProtocolService, prv api.Provider) error {
			icsvc, ok := svc.(*issuecredential.Service)
			if !ok {
				return fmt.Errorf("expected issue credential ProtocolService to be a %T", issuecredential.Service{})
			}

			err := icsvc.Initialize(prv)
			if err != nil {
				return err
			}

			// sets default middleware to the service
			icsvc.Use(mdissuecredential.SaveCredentials(prv))

			return nil
		},
	}
}

func newPresentProofSvc() api.ProtocolSvcCreator {
	return api.ProtocolSvcCreator{
		Create: func(prv api.Provider) (dispatcher.ProtocolService, error) {
			return &presentproof.Service{}, nil
		},
		Init: func(svc dispatcher.ProtocolService, prv api.Provider) error {
			ppsvc, ok := svc.(*presentproof.Service)
			if !ok {
				return fmt.Errorf("expected present proof ProtocolService to be a %T", presentproof.Service{})
			}

			err := ppsvc.Initialize(prv)
			if err != nil {
				return err
			}

			// sets default middleware to the service
			ppsvc.Use(
				mdpresentproof.SavePresentation(prv),
				mdpresentproof.PresentationDefinition(prv,
					mdpresentproof.WithAddProofFn(mdpresentproof.AddBBSProofFn(prv)),
				),
			)

			return nil
		},
	}
}

func newRouteSvc() api.ProtocolSvcCreator {
	return api.ProtocolSvcCreator{
		Create: func(prv api.Provider) (dispatcher.ProtocolService, error) {
			return &mediator.Service{}, nil
		},
	}
}

func newMessagePickupSvc() api.ProtocolSvcCreator {
	return api.ProtocolSvcCreator{
		Create: func(prv api.Provider) (dispatcher.ProtocolService, error) {
			return &messagepickup.Service{}, nil
		},
	}
}

func newOutOfBandSvc() api.ProtocolSvcCreator {
	return api.ProtocolSvcCreator{
		Create: func(prv api.Provider) (dispatcher.ProtocolService, error) {
			return &outofband.Service{}, nil
		},
	}
}

func newOutOfBandV2Svc() api.ProtocolSvcCreator {
	return api.ProtocolSvcCreator{
		Create: func(prv api.Provider) (dispatcher.ProtocolService, error) {
			return &outofbandv2.Service{}, nil
		},
		Init: func(svc dispatcher.ProtocolService, prv api.Provider) error {
			oobv2svc, ok := svc.(*outofbandv2.Service)
			if !ok {
				return fmt.Errorf("expected OOB V2 ProtocolService to be a %T", outofbandv2.Service{})
			}

			err := oobv2svc.Initialize(prv)
			if err != nil {
				return err
			}

			return nil
		},
	}
}

func setDefaultKMSCryptOpts(frameworkOpts *Aries) error {
	if frameworkOpts.kmsCreator == nil {
		frameworkOpts.kmsCreator = func(provider kms.Provider) (kms.KeyManager, error) {
			return localkms.New(defaultMasterKeyURI, provider)
		}
	}

	if frameworkOpts.crypto == nil {
		// create default tink crypto if not passed in frameworkOpts
		cr, err := tinkcrypto.New()
		if err != nil {
			return fmt.Errorf("context creation failed: %w", err)
		}

		frameworkOpts.crypto = cr
	}

	return nil
}

func setAdditionalDefaultOpts(frameworkOpts *Aries) error {
	err := setDefaultKMSCryptOpts(frameworkOpts)
	if err != nil {
		return err
	}

	if frameworkOpts.keyType == "" {
		frameworkOpts.keyType = kms.ED25519Type
	}

	if frameworkOpts.keyAgreementType == "" {
		frameworkOpts.keyAgreementType = kms.X25519ECDHKWType
	}

	if frameworkOpts.packerCreator == nil {
		frameworkOpts.packerCreator = func(provider packer.Provider) (packer.Packer, error) {
			return legacy.New(provider), nil
		}

		frameworkOpts.packerCreators = []packer.Creator{
			func(provider packer.Provider) (packer.Packer, error) {
				return legacy.New(provider), nil
			},
			func(provider packer.Provider) (packer.Packer, error) {
				return authcrypt.New(provider, jose.A256CBCHS512)
			},
			func(provider packer.Provider) (packer.Packer, error) {
				return anoncrypt.New(provider, jose.A256GCM)
			},
		}
	}

	if frameworkOpts.packagerCreator == nil {
		frameworkOpts.packagerCreator = func(prov packager.Provider) (transport.Packager, error) {
			return packager.New(prov)
		}
	}

	if frameworkOpts.protocolStateStoreProvider == nil {
		frameworkOpts.protocolStateStoreProvider = storeProvider()
	}

	if frameworkOpts.msgSvcProvider == nil {
		frameworkOpts.msgSvcProvider = &noOpMessageServiceProvider{}
	}

	if frameworkOpts.mediaTypeProfiles == nil {
		// For now only set legacy media type profile to match default key type and primary packer above.
		// Using media type profile, not just a media type, in order to align with OOB invitations' Accept header.
		// TODO once keyAgreement is added in the packers, this can be switched to DIDcomm V2 media type as well as
		// 		switching legacyPacker with authcrtypt as primary packer and using an ECDH-1PU key as default key above.
		frameworkOpts.mediaTypeProfiles = []string{transport.MediaTypeAIP2RFC0019Profile}
	}

	return nil
}

func assignVerifiableStoreIfNeeded(aries *Aries, storeProvider storage.Provider) error {
	if aries.verifiableStore != nil {
		return nil
	}

	provider, err := context.New(
		context.WithStorageProvider(storeProvider),
		context.WithJSONLDDocumentLoader(aries.documentLoader),
	)
	if err != nil {
		return fmt.Errorf("verifiable store initialization failed : %w", err)
	}

	aries.verifiableStore, err = verifiable.New(provider)
	if err != nil {
		return fmt.Errorf("can't initialize verifaible store : %w", err)
	}

	return nil
}

func createDefSecretLock(opts *Aries) error {
	// default lock is noop, ie keys are not secure by default.
	// users of the framework must pre-build a secure lock and pass it in as an option
	opts.secretLock = &noop.NoLock{}

	return nil
}

// noOpMessageServiceProvider returns noop message service provider.
type noOpMessageServiceProvider struct{}

// Services returns empty list of services for noOpMessageServiceProvider.
func (n *noOpMessageServiceProvider) Services() []dispatcher.MessageService {
	return []dispatcher.MessageService{}
}
