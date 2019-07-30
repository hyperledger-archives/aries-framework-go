/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"fmt"
	"log"
	"os"

	logapi "github.com/hyperledger/aries-framework-go/pkg/common/log"
)

//providerOpts contains options for initializing Moduled logging provider
type providerOpts struct {
	provider logapi.LoggerProvider
}

//ProviderOpts is option to provide logger provider opts for initializing Moduled logging provider
type ProviderOpts func(opts *providerOpts)

//WithCustomProvider can be used to provide custom logger provider for moduled logger
func WithCustomProvider(provider logapi.LoggerProvider) ProviderOpts {
	return func(opts *providerOpts) {
		opts.provider = provider
	}
}

//NewModLogProvider returns logger provider for moduled level based logger
func NewModLogProvider(opts ...ProviderOpts) *LogProvider {
	providerOpts := &providerOpts{}
	for _, opt := range opts {
		opt(providerOpts)
	}
	return &LogProvider{providerOpts.provider}
}

// LogProvider is the default logger implementation
type LogProvider struct {
	customProvider logapi.LoggerProvider
}

//GetLogger returns moduled logger implementation.
func (p *LogProvider) GetLogger(module string) logapi.Logger {
	var logger logapi.Logger
	if p.customProvider != nil {
		logger = p.customProvider.GetLogger(module)
	} else {
		logger = &defLog{logger: log.New(os.Stdout, fmt.Sprintf(logPrefixFormatter, module), log.Ldate|log.Ltime|log.LUTC), module: module}
	}
	return &modLog{logger: logger, module: module}
}
