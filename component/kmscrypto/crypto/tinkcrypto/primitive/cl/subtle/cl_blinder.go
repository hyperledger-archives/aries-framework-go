//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/internal/ursautil"
)

// CLBlinder is used for blinding CL MasterSecret with arbitrary values.
type CLBlinder struct {
	masterSecret    *ursa.MasterSecret
	masterSecretStr string
}

// NewCLBlinder creates a new instance of CL Blinder with the provided privateKey.
func NewCLBlinder(key []byte) (*CLBlinder, error) {
	ms, err := ursa.MasterSecretFromJSON(key)
	if err != nil {
		return nil, fmt.Errorf("cl_prover: invalid master secret json: %w", err)
	}

	msJSON, err := ms.ToJSON()
	if err != nil {
		return nil, err
	}

	m := struct {
		MS string `json:"ms"`
	}{}

	err = json.Unmarshal(msJSON, &m)
	if err != nil {
		return nil, err
	}

	return &CLBlinder{
		masterSecret:    ms,
		masterSecretStr: m.MS,
	}, nil
}

// Blind will blind provided values with MasterSecret
// returns:
//
//	blinded values in []byte
//	error in case of errors
func (s *CLBlinder) Blind(
	values map[string]interface{},
) ([]byte, error) {
	_credValues, err := ursautil.BuildValues(values, &s.masterSecretStr)
	if err != nil {
		return nil, err
	}

	defer _credValues.Free() // nolint: errcheck

	credValues, err := _credValues.ToJSON()
	if err != nil {
		return nil, err
	}

	return credValues, nil
}

// Free ursa.MasterSecret ptr.
func (s *CLBlinder) Free() error {
	err := s.masterSecret.Free()
	if err != nil {
		return err
	}

	return nil
}
