/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// UniversityDegree university degree.
type UniversityDegree struct {
	Type       string `json:"type,omitempty"`
	Name       string `json:"name,omitempty"`
	College    string `json:"college,omitempty"`
	University string `json:"university,omitempty"`
}

// UniversityDegreeSubject subject of university degree.
type UniversityDegreeSubject struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Spouse string `json:"spouse,omitempty"`

	Degree UniversityDegree `json:"degree,omitempty"`
}

func mapUniversityDegreeSubject(subjects []Subject) *UniversityDegreeSubject {
	if len(subjects) != 1 {
		return nil
	}

	subject := &subjects[0]
	customFields := subject.CustomFields
	udSubject := &UniversityDegreeSubject{
		ID:     subject.ID,
		Name:   safeStringValue(customFields["name"]),
		Spouse: safeStringValue(customFields["spouse"]),
	}

	degreeValue, ok := customFields["degree"]
	if !ok {
		return udSubject
	}

	degreeMap, ok := degreeValue.(map[string]interface{})
	if !ok {
		return udSubject
	}

	udDegree := &udSubject.Degree
	udDegree.Type = safeStringValue(degreeMap["type"])
	udDegree.Name = safeStringValue(degreeMap["name"])
	udDegree.College = safeStringValue(degreeMap["college"])
	udDegree.University = safeStringValue(degreeMap["university"])

	return udSubject
}

// UniversityDegreeCredential University Degree credential, from examples of https://w3c.github.io/vc-data-model
type UniversityDegreeCredential struct {
	Base Credential `json:"-"`

	Subject *UniversityDegreeSubject `json:"credentialSubject,omitempty"`
}

func NewUniversityDegreeCredential(t *testing.T, vcData []byte,
	opts ...CredentialOpt) (*UniversityDegreeCredential, error) {
	cred, err := parseTestCredential(t, vcData, opts...)
	if err != nil {
		return nil, fmt.Errorf("new university degree credential: %w", err)
	}

	// One way to build custom credential subject is to convert []Subject to the custom credential.
	udc := UniversityDegreeCredential{
		Base:    *cred,
		Subject: mapUniversityDegreeSubject(credSubjects(cred)),
	}

	// The other way is to marshal credential subject and unmarshal back to custom subject structure.
	subjects, ok := cred.Subject.([]Subject)
	if !ok {
		return nil, errors.New("expected subject of []Subject type")
	}

	if len(subjects) != 1 {
		return nil, errors.New("expected a single subject")
	}

	subjectBytes, err := json.Marshal(subjects[0])
	if err != nil {
		return nil, fmt.Errorf("new university degree credential subject: %w", err)
	}

	err = json.Unmarshal(subjectBytes, &udc.Subject)
	if err != nil {
		return nil, fmt.Errorf("new university degree credential subject: %w", err)
	}

	return &udc, nil
}

func credSubjects(vc *Credential) []Subject {
	if vc.Subject == nil {
		return nil
	}

	if subjects, ok := vc.Subject.([]Subject); ok {
		return subjects
	}

	return nil
}

func TestCredentialExtensibility(t *testing.T) {
	udCredential := `

{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.edu/credentials/1872",
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },

  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  },

  "issuanceDate": "2010-01-01T19:23:24Z",

  "expirationDate": "2020-01-01T19:23:24Z",

  "credentialStatus": {
    "id": "https://example.edu/status/24",
    "type": "CredentialStatusList2017"
  },

  "evidence": [{
    "id": "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231",
    "type": ["DocumentVerification"],
    "verifier": "https://example.edu/issuers/14",
    "evidenceDocument": "DriversLicense",
    "subjectPresence": "Physical",
    "documentPresence": "Physical"
  },{
    "id": "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192dxyzab",
    "type": ["SupportingActivity"],
    "verifier": "https://example.edu/issuers/14",
    "evidenceDocument": "Fluid Dynamics Focus",
    "subjectPresence": "Digital",
    "documentPresence": "Digital"
  }],

  "termsOfUse": [
    {
      "type": "IssuerPolicy",
      "id": "http://example.com/policies/credential/4",
      "profile": "http://example.com/profiles/credential",
      "prohibition": [
        {
          "assigner": "https://example.edu/issuers/14",
          "assignee": "AllVerifiers",
          "target": "http://example.edu/credentials/3732",
          "action": [
            "Archival"
          ]
        }
      ]
    }
  ],

  "refreshService": {
    "id": "https://example.edu/refresh/3732",
    "type": "ManualRefreshService2018"
  }
}
`

	cred, err := parseTestCredential(t, []byte(udCredential))
	require.NoError(t, err)
	require.NotNil(t, cred)

	udc, err := NewUniversityDegreeCredential(t, []byte(udCredential))
	require.NoError(t, err)

	// base Credential part is the same
	require.Equal(t, *cred, udc.Base)

	// default issuer credential decoder is applied (i.e. not re-written by new custom decoder)
	require.NotNil(t, cred.Issuer)
	require.Equal(t, cred.Issuer.ID, "did:example:76e12ec712ebc6f1c221ebfeb1f")
	require.Equal(t, cred.Issuer.CustomFields["name"], "Example University")

	// new mapping is applied
	subj := udc.Subject
	require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subj.ID)
	require.Equal(t, "BachelorDegree", subj.Degree.Type)
	require.Equal(t, "Jayden Doe", subj.Name)
	require.Equal(t, "did:example:c276e12ec21ebfeb1f712ebc6f1", subj.Spouse)
}
