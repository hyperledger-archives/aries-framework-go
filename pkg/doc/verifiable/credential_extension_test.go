/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// UniversityDegree university degree
type UniversityDegree struct {
	Type       string `json:"type,omitempty"`
	Name       string `json:"name,omitempty"`
	College    string `json:"college,omitempty"`
	University string `json:"university,omitempty"`
}

// UniversityDegreeSubject subject of university degree
type UniversityDegreeSubject struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Spouse string `json:"spouse,omitempty"`

	Degree UniversityDegree `json:"degree,omitempty"`
}

// UniversityDegreeCredential University Degree credential, from examples of https://w3c.github.io/vc-data-model
type UniversityDegreeCredential struct {
	Base Credential `json:"-"`

	Subject *UniversityDegreeSubject `json:"credentialSubject,omitempty"`
}

func NewUniversityDegreeCredential(vcData []byte, opts ...CredentialOpt) (*UniversityDegreeCredential, error) {
	cred, credBytes, err := NewCredential(vcData, opts...)
	if err != nil {
		return nil, fmt.Errorf("new university degree credential: %w", err)
	}

	udc := UniversityDegreeCredential{
		Base: *cred,
	}

	err = json.Unmarshal(credBytes, &udc)
	if err != nil {
		return nil, fmt.Errorf("new university degree credential: %w", err)
	}

	return &udc, nil
}

func TestCredentialExtensibility(t *testing.T) {
	cred, _, err := NewCredential([]byte(validCredential))
	require.NoError(t, err)
	require.NotNil(t, cred)

	udc, err := NewUniversityDegreeCredential([]byte(validCredential))
	require.NoError(t, err)

	// base Credential part is the same
	require.Equal(t, *cred, udc.Base)

	// default issuer credential decoder is applied (i.e. not re-written by new custom decoder)
	require.NotNil(t, cred.Issuer)
	require.Equal(t, cred.Issuer.ID, "did:example:76e12ec712ebc6f1c221ebfeb1f")
	require.Equal(t, cred.Issuer.Name, "Example University")

	// new mapping is applied
	subj := udc.Subject
	require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subj.ID)
	require.Equal(t, "BachelorDegree", subj.Degree.Type)
	require.Equal(t, "MIT", subj.Degree.University)
	require.Equal(t, "Jayden Doe", subj.Name)
	require.Equal(t, "did:example:c276e12ec21ebfeb1f712ebc6f1", subj.Spouse)
}
