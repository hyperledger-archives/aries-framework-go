/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package update implements sidetree update did option
//
package update

import (
	"crypto"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrdoc "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/doc"
)

// Option is a update DID option.
type Option func(opts *Opts)

// Opts update did opts.
type Opts struct {
	AddPublicKeys       []vdrdoc.PublicKey
	AddServices         []docdid.Service
	RemovePublicKeys    []string
	RemoveServices      []string
	GetEndpoints        func() ([]string, error)
	NextUpdatePublicKey crypto.PublicKey
	SigningKey          crypto.PrivateKey
	SigningKeyID        string
	RevealValue         string
	MultiHashAlgorithm  uint
}

// WithAddPublicKey add DID public key.
func WithAddPublicKey(publicKey *vdrdoc.PublicKey) Option {
	return func(opts *Opts) {
		opts.AddPublicKeys = append(opts.AddPublicKeys, *publicKey)
	}
}

// WithAddService set services to be added.
func WithAddService(service *docdid.Service) Option {
	return func(opts *Opts) {
		opts.AddServices = append(opts.AddServices, *service)
	}
}

// WithRemovePublicKey set remove public key id.
func WithRemovePublicKey(publicKeyID string) Option {
	return func(opts *Opts) {
		opts.RemovePublicKeys = append(opts.RemovePublicKeys, publicKeyID)
	}
}

// WithRemoveService set remove service id.
func WithRemoveService(serviceID string) Option {
	return func(opts *Opts) {
		opts.RemoveServices = append(opts.RemoveServices, serviceID)
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

// WithEndpoints get endpoints.
func WithEndpoints(getEndpoints func() ([]string, error)) Option {
	return func(opts *Opts) {
		opts.GetEndpoints = getEndpoints
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
