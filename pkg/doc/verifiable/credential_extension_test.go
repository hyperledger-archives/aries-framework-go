/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
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
	Base Credential

	Subject *UniversityDegreeSubject `json:"credentialSubject,omitempty"`
}

func (udc *UniversityDegreeCredential) credential() *Credential {
	return &udc.Base
}

func (udc *UniversityDegreeCredential) decode(dataJSON []byte, credential *Credential) error {
	return json.Unmarshal(dataJSON, udc)
}

func TestCredentialExtensibility(t *testing.T) {
	udc := &UniversityDegreeCredential{}
	cred, err := NewCredential(
		[]byte(validCredential),
		WithDecoders([]CredentialDecoder{udc.decode}),
		WithTemplate(udc.credential),
	)

	require.NoError(t, err)
	require.NotNil(t, cred)
	require.Equal(t, &udc.Base, cred)

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
