/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package recovery implements sidetree recovery did option
//
package recovery

import (
	"crypto"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrdoc "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/doc"
)

// Opts recover did opts.
type Opts struct {
	PublicKeys            []vdrdoc.PublicKey
	Services              []docdid.Service
	GetEndpoints          func() ([]string, error)
	NextRecoveryPublicKey crypto.PublicKey
	NextUpdatePublicKey   crypto.PublicKey
	SigningKey            crypto.PrivateKey
	SigningKeyID          string
	RevealValue           string
	MultiHashAlgorithm    uint
}

// Option is a recover DID option.
type Option func(opts *Opts)

// WithPublicKey add DID public key.
func WithPublicKey(publicKey *vdrdoc.PublicKey) Option {
	return func(opts *Opts) {
		opts.PublicKeys = append(opts.PublicKeys, *publicKey)
	}
}

// WithService add service.
func WithService(service *docdid.Service) Option {
	return func(opts *Opts) {
		opts.Services = append(opts.Services, *service)
	}
}

// WithEndpoints get endpoints.
func WithEndpoints(getEndpoints func() ([]string, error)) Option {
	return func(opts *Opts) {
		opts.GetEndpoints = getEndpoints
	}
}

// WithNextRecoveryPublicKey set next recovery public key.
func WithNextRecoveryPublicKey(nextRecoveryPublicKey crypto.PublicKey) Option {
	return func(opts *Opts) {
		opts.NextRecoveryPublicKey = nextRecoveryPublicKey
	}
}

// WithNextUpdatePublicKey set next update public key.
func WithNextUpdatePublicKey(nextUpdatePublicKey crypto.PublicKey) Option {
	return func(opts *Opts) {
		opts.NextUpdatePublicKey = nextUpdatePublicKey
	}
}

// WithSigningKey set signing key.
func WithSigningKey(signingKey crypto.PrivateKey) Option {
	return func(opts *Opts) {
		opts.SigningKey = signingKey
	}
}

// WithSigningKeyID set signing key id.
func WithSigningKeyID(id string) Option {
	return func(opts *Opts) {
		opts.SigningKeyID = id
	}
}

// WithRevealValue sets reveal value.
func WithRevealValue(rv string) Option {
	return func(opts *Opts) {
		opts.RevealValue = rv
	}
}

// WithMultiHashAlgorithm set multi hash algorithm for sidetree request.
func WithMultiHashAlgorithm(multiHashAlgorithm uint) Option {
	return func(opts *Opts) {
		opts.MultiHashAlgorithm = multiHashAlgorithm
	}
}
