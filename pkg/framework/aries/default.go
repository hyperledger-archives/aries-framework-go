/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
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
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	didcommtransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
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
func defFrameworkOpts(frameworkOpts *Aries) error {
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

	err := assignVerifiableStoreIfNeeded(frameworkOpts, frameworkOpts.storeProvider)
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
		newIntroduceSvc(), newIssueCredentialSvc(), newPresentProofSvc())

	if frameworkOpts.secretLock == nil && frameworkOpts.kmsCreator == nil {
		err = createDefSecretLock(frameworkOpts)
		if err != nil {
			return err
		}
	}

	if frameworkOpts.kmsCreator == nil {
		frameworkOpts.kmsCreator = func(provider kms.Provider) (kms.KeyManager, error) {
			return localkms.New(defaultMasterKeyURI, provider)
		}
	}

	return setAdditionalDefaultOpts(frameworkOpts)
}

func newExchangeSvc() api.ProtocolSvcCreator {
	return func(prv api.Provider) (dispatcher.ProtocolService, error) {
		return didexchange.New(prv)
	}
}

func newIntroduceSvc() api.ProtocolSvcCreator {
	return func(prv api.Provider) (dispatcher.ProtocolService, error) {
		return introduce.New(prv)
	}
}

func newIssueCredentialSvc() api.ProtocolSvcCreator {
	return func(prv api.Provider) (dispatcher.ProtocolService, error) {
		service, err := issuecredential.New(prv)
		if err != nil {
			return nil, err
		}

		// sets default middleware to the service
		service.Use(mdissuecredential.SaveCredentials(prv))

		return service, nil
	}
}

func newPresentProofSvc() api.ProtocolSvcCreator {
	return func(prv api.Provider) (dispatcher.ProtocolService, error) {
		service, err := presentproof.New(prv)
		if err != nil {
			return nil, err
		}

		// sets default middleware to the service
		service.Use(
			mdpresentproof.SavePresentation(prv),
			mdpresentproof.PresentationDefinition(prv,
				mdpresentproof.WithAddProofFn(mdpresentproof.AddBBSProofFn(prv)),
			),
		)

		return service, nil
	}
}

func newRouteSvc() api.ProtocolSvcCreator {
	return func(prv api.Provider) (dispatcher.ProtocolService, error) {
		return mediator.New(prv)
	}
}

func newMessagePickupSvc() api.ProtocolSvcCreator {
	return func(prv api.Provider) (dispatcher.ProtocolService, error) {
		tp, ok := prv.(didcommtransport.Provider)
		if !ok {
			return nil, errors.New("failed to cast transport provider")
		}

		return messagepickup.New(prv, tp)
	}
}

func newOutOfBandSvc() api.ProtocolSvcCreator {
	return func(prv api.Provider) (dispatcher.ProtocolService, error) {
		return outofband.New(prv)
	}
}

func setAdditionalDefaultOpts(frameworkOpts *Aries) error {
	if frameworkOpts.kmsCreator == nil {
		frameworkOpts.kmsCreator = func(provider kms.Provider) (kms.KeyManager, error) {
			return localkms.New("local-lock://", provider)
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

	if frameworkOpts.packerCreator == nil {
		frameworkOpts.packerCreator = func(provider packer.Provider) (packer.Packer, error) {
			return legacy.New(provider), nil
		}

		frameworkOpts.packerCreators = []packer.Creator{
			func(provider packer.Provider) (packer.Packer, error) {
				return legacy.New(provider), nil
			},
			func(provider packer.Provider) (packer.Packer, error) {
				return authcrypt.New(provider, jose.A256GCM)
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

	return nil
}

func assignVerifiableStoreIfNeeded(aries *Aries, storeProvider storage.Provider) error {
	if aries.verifiableStore != nil {
		return nil
	}

	provider, err := context.New(context.WithStorageProvider(storeProvider))
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
