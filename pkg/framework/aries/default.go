/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packager"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	jwe "github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/jwe/authcrypt"
	legacy "github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/legacy/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	didcommtrans "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

//nolint:gochecknoglobals
var (
	defaultInboundPort = ":8090"
)

func inboundTransport() (didcommtrans.InboundTransport, error) {
	inbound, err := arieshttp.NewInbound(defaultInboundPort, "")
	if err != nil {
		return nil, fmt.Errorf("http inbound transport initialization failed: %w", err)
	}

	return inbound, nil
}

// defFrameworkOpts provides default framework options
func defFrameworkOpts(frameworkOpts *Aries) error {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/209 Move default providers to the sub-package
	if frameworkOpts.outboundTransport == nil {
		outbound, err := arieshttp.NewOutbound(arieshttp.WithOutboundHTTPClient(&http.Client{}))
		if err != nil {
			return fmt.Errorf("http outbound transport initialization failed: %w", err)
		}

		frameworkOpts.outboundTransport = outbound
	}

	if frameworkOpts.storeProvider == nil {
		storeProv, err := storeProvider()
		if err != nil {
			return fmt.Errorf("resolver initialization failed : %w", err)
		}

		frameworkOpts.storeProvider = storeProv
	}

	if frameworkOpts.inboundTransport == nil {
		inbound, err := inboundTransport()
		if err != nil {
			return fmt.Errorf("http inbound transport initialization failed: %w", err)
		}

		frameworkOpts.inboundTransport = inbound
	}

	frameworkOpts.protocolSvcCreators = append(frameworkOpts.protocolSvcCreators, newExchangeSvc())

	return setAdditionalDefaultOpts(frameworkOpts)
}

func newExchangeSvc() api.ProtocolSvcCreator {
	return func(prv api.Provider) (dispatcher.Service, error) {
		return didexchange.New(prv)
	}
}

func setAdditionalDefaultOpts(frameworkOpts *Aries) error {
	if frameworkOpts.kmsCreator == nil {
		frameworkOpts.kmsCreator = func(provider api.Provider) (api.CloseableKMS, error) {
			return kms.New(provider)
		}
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

	if frameworkOpts.outboundDispatcherCreator == nil {
		frameworkOpts.outboundDispatcherCreator = func(prv dispatcher.Provider) (dispatcher.Outbound, error) {
			return dispatcher.NewOutbound(prv), nil
		}
	}

	if frameworkOpts.transientStoreProvider == nil {
		var err error
		frameworkOpts.transientStoreProvider, err = transientStoreProvider()

		if err != nil {
			return err
		}
	}

	return nil
}
