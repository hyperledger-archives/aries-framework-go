/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package create implements create did option
//
package create

import (
	"crypto"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/doc"
)

// Opts create did opts.
type Opts struct {
	PublicKeys             []doc.PublicKey
	Services               []docdid.Service
	GetEndpoints           func() ([]string, error)
	RecoveryPublicKey      crypto.PublicKey
	UpdatePublicKey        crypto.PublicKey
	SigningKey             crypto.PrivateKey
	SigningKeyID           string
	MultiHashAlgorithm     uint
	DefaultServiceType     string
	DefaultServiceEndpoint string
	EncryptionKey          *doc.PublicKey
}

// Option is a create DID option.
type Option func(opts *Opts)

// WithPublicKey add DID public key.
func WithPublicKey(publicKey *doc.PublicKey) Option {
	return func(opts *Opts) {
		opts.PublicKeys = append(opts.PublicKeys, *publicKey)
	}
}

// WithEndpoints get endpoints.
func WithEndpoints(getEndpoints func() ([]string, error)) Option {
	return func(opts *Opts) {
		opts.GetEndpoints = getEndpoints
	}
}

// WithService add service.
func WithService(service *docdid.Service) Option {
	return func(opts *Opts) {
		opts.Services = append(opts.Services, *service)
	}
}

// WithRecoveryPublicKey set recovery public key.
func WithRecoveryPublicKey(recoveryPublicKey crypto.PublicKey) Option {
	return func(opts *Opts) {
		opts.RecoveryPublicKey = recoveryPublicKey
	}
}

// WithUpdatePublicKey set update public key.
func WithUpdatePublicKey(updatePublicKey crypto.PublicKey) Option {
	return func(opts *Opts) {
		opts.UpdatePublicKey = updatePublicKey
	}
}

// WithMultiHashAlgorithm set multi hash algorithm for sidetree request.
func WithMultiHashAlgorithm(multiHashAlgorithm uint) Option {
	return func(opts *Opts) {
		opts.MultiHashAlgorithm = multiHashAlgorithm
	}
}

// WithDefaultServiceType service type of DID document to be created.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2451
func WithDefaultServiceType(serviceType string) Option {
	return func(opts *Opts) {
		opts.DefaultServiceType = serviceType
	}
}

// WithDefaultServiceEndpoint service.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2451
func WithDefaultServiceEndpoint(endpoint string) Option {
	return func(opts *Opts) {
		opts.DefaultServiceEndpoint = endpoint
	}
}

// WithEncryptionKey allows for setting encryption key.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2452
func WithEncryptionKey(encryptionKey *doc.PublicKey) Option {
	return func(opts *Opts) {
		opts.EncryptionKey = encryptionKey
	}
}
