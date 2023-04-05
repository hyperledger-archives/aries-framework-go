//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ursautil

import (
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
)

// BuildSchema is used for building a schema and a non-schema for a CredDef.
func BuildSchema(attrs []string) (*ursa.CredentialSchemaHandle, *ursa.NonCredentialSchemaHandle, error) {
	schemaBuilder, err := ursa.NewCredentialSchemaBuilder()
	if err != nil {
		return nil, nil, err
	}

	for _, attr := range attrs {
		err = schemaBuilder.AddAttr(attr)
		if err != nil {
			return nil, nil, err
		}
	}

	schema, err := schemaBuilder.Finalize()
	if err != nil {
		return nil, nil, err
	}

	nonSchemaBuilder, err := ursa.NewNonCredentialSchemaBuilder()
	if err != nil {
		return nil, nil, err
	}

	err = nonSchemaBuilder.AddAttr("master_secret")
	if err != nil {
		return nil, nil, err
	}

	nonSchema, err := nonSchemaBuilder.Finalize()
	if err != nil {
		return nil, nil, err
	}

	return schema, nonSchema, nil
}

// BuildValues is used for building blinded values.
func BuildValues(values map[string]interface{}, masterSecretStr *string) (*ursa.CredentialValues, error) {
	valuesBuilder, err := ursa.NewValueBuilder()
	if err != nil {
		return nil, err
	}

	if masterSecretStr != nil {
		err = valuesBuilder.AddDecHidden("master_secret", *masterSecretStr)
		if err != nil {
			return nil, err
		}
	}

	for k, v := range values {
		_, enc := ursa.EncodeValue(v)

		err = valuesBuilder.AddDecKnown(k, enc)
		if err != nil {
			return nil, err
		}
	}

	credentialValues, err := valuesBuilder.Finalize()
	if err != nil {
		return nil, err
	}

	return credentialValues, nil
}
