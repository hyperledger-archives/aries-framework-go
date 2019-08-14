/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/factory/transport"
)

// defFramework provides default framework configs
type defFramework struct{}

// transportProviderFactory provides default Outbound Transport provider factory
func (d defFramework) transportProviderFactory() api.TransportProviderFactory {
	return transport.NewProviderFactory()
}

// defFrameworkOpts provides default framework options
func defFrameworkOpts() []Option {
	// get the default framework configs
	def := defFramework{}

	var opts []Option
	// protocol provider factory
	opt := WithTransportProviderFactory(def.transportProviderFactory())
	opts = append(opts, opt)

	return opts
}
