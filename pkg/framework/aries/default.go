/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packager"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	jwe "github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/jwe/authcrypt"
	legacy "github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/legacy/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/route"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
)

// defFrameworkOpts provides default framework options
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
		storeProv, err := storeProvider()
		if err != nil {
			return fmt.Errorf("resolver initialization failed : %w", err)
		}

		frameworkOpts.storeProvider = storeProv
	}

	// order is important as DIDExchange service depends on Route service and Introduce depends on DIDExchange
	frameworkOpts.protocolSvcCreators = append(frameworkOpts.protocolSvcCreators,
		newRouteSvc(), newExchangeSvc(), newIntroduceSvc())

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

func newRouteSvc() api.ProtocolSvcCreator {
	return func(prv api.Provider) (dispatcher.ProtocolService, error) {
		return route.New(prv)
	}
}

func setAdditionalDefaultOpts(frameworkOpts *Aries) error {
	if frameworkOpts.legacyKmsCreator == nil {
		frameworkOpts.legacyKmsCreator = func(provider api.Provider) (api.CloseableKMS, error) {
			return legacykms.New(provider)
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
				return jwe.New(provider, jwe.XC20P)
			},
		}
	}

	if frameworkOpts.packagerCreator == nil {
		frameworkOpts.packagerCreator = func(prov packager.Provider) (transport.Packager, error) {
			return packager.New(prov)
		}
	}

	if frameworkOpts.transientStoreProvider == nil {
		var err error
		frameworkOpts.transientStoreProvider, err = transientStoreProvider()

		if err != nil {
			return err
		}
	}

	if frameworkOpts.msgSvcProvider == nil {
		frameworkOpts.msgSvcProvider = &noOpMessageServiceProvider{}
	}

	return nil
}

// noOpMessageServiceProvider returns noop message service provider
type noOpMessageServiceProvider struct{}

// Services returns empty list of services for noOpMessageServiceProvider
func (n *noOpMessageServiceProvider) Services() []dispatcher.MessageService {
	return []dispatcher.MessageService{}
}
