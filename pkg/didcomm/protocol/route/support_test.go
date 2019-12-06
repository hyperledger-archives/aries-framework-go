/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/dispatcher"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// mock route coordination provider
type mockProvider struct {
	openStoreErr error
}

func (p *mockProvider) OutboundDispatcher() dispatcher.Outbound {
	return &mockdispatcher.MockOutbound{}
}

func (p *mockProvider) StorageProvider() storage.Provider {
	if p.openStoreErr != nil {
		return &mockstore.MockStoreProvider{ErrOpenStoreHandle: p.openStoreErr}
	}

	return mockstore.NewMockStoreProvider()
}

func (p *mockProvider) InboundTransportEndpoint() string {
	return "ws://example.com"
}

func (p *mockProvider) KMS() kms.KeyManager {
	return &mockkms.CloseableKMS{CreateEncryptionKeyValue: "sample-key"}
}
