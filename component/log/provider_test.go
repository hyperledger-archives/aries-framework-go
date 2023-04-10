/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"sync"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/log/internal/modlog"
	"github.com/hyperledger/aries-framework-go/spi/log"
)

// TestDefaultLogger tests custom logging feature when custom logging provider is supplied through 'Initialize()' call.
func TestCustomLogger(t *testing.T) {
	defer func() { loggerProviderOnce = sync.Once{} }()

	const module = "sample-module"

	// initialize logger provider with custom logger provider
	Initialize(newCustomProvider(module))

	// get logger instance
	logger := New(module)

	modlog.VerifyCustomLogger(t, logger, module)
}

// newCustomProvider return new sample logging provider to demonstrate custom logging provider.
func newCustomProvider(module string) *sampleProvider {
	return &sampleProvider{modlog.GetSampleCustomLogger(module)}
}

// sampleProvider is a custom logging provider.
type sampleProvider struct {
	logger log.Logger
}

// GetLogger returns custom logger implementation.
func (p *sampleProvider) GetLogger(module string) log.Logger {
	return p.logger
}
