/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"fmt"
	"log"
	"os"

	"github.com/hyperledger/aries-framework-go/pkg/common/logging/api"
)

type providerOpts struct {
	customProvider api.LoggerProvider
}

//ModuledLoggerOpts is option to provide logger provider opts for initializing Moduled logging provider
type ModuledLoggerOpts func(opts *providerOpts)

//WithCustomProvider can be used to provide custom logger provider for moduled logger
func WithCustomProvider(customProvider api.LoggerProvider) ModuledLoggerOpts {
	return func(opts *providerOpts) {
		opts.customProvider = customProvider
	}
}

//ModuledLoggerProvider returns logger provider for moduled level based logger
func ModuledLoggerProvider(opts ...ModuledLoggerOpts) api.LoggerProvider {
	providerOpts := &providerOpts{}
	for _, opt := range opts {
		opt(providerOpts)
	}
	return &provider{providerOpts.customProvider}
}

// provider is the default logger implementation
type provider struct {
	customProvider api.LoggerProvider
}

//GetLogger returns moduled logger implementation
func (p *provider) GetLogger(module string) api.Logger {
	if p.customProvider != nil {
		return &modLog{logger: p.customProvider.GetLogger(module), module: module}
	}
	newDefLogger := log.New(os.Stdout, fmt.Sprintf(logPrefixFormatter, module), log.Ldate|log.Ltime|log.LUTC)
	return &defLog{logger: newDefLogger, module: module}
}
