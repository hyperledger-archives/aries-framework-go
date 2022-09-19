/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didconfig

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
)

const (
	testDID    = "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM"
	testDomain = "https://identity.foundation"
)

func TestParseOfNull(t *testing.T) {
	err := VerifyDIDAndDomain([]byte("null"), testDID, testDomain)
	require.Error(t, err)
	require.Contains(t, err.Error(), "DID configuration payload is not provided")
}

func TestParseLinkedData(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader(ldcontext.Document{
		URL:     ContextV1,
		Content: json.RawMessage(didConfigCtx),
	})
	require.NoError(t, err)

	t.Run("success - default options", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedData), testDID, testDomain)
		require.NoError(t, err)
	})

	t.Run("success - loader provided", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedData), testDID, testDomain,
			WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)
	})

	t.Run("success - registry provided", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedData), testDID, testDomain,
			WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))))
		require.NoError(t, err)
	})

	t.Run("error - invalid proof", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedDataInvalidProof), testDID, testDomain,
			WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))))
		require.Error(t, err)
		require.Contains(t, err.Error(), "domain linkage credential(s) with valid proof not found")
	})

	t.Run("error - origins do not match", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedData), testDID, "https://different.com",
			WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))))
		require.Error(t, err)

		require.Contains(t, err.Error(), "domain linkage credential(s) not found")
	})

	t.Run("error - DIDs do not match", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedData), "did:web:different", testDomain,
			WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))))
		require.Error(t, err)

		require.Contains(t, err.Error(), "domain linkage credential(s) not found")
	})

	t.Run("error - origin invalid", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedData), testDID, "://different.com",
			WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))))
		require.Error(t, err)
		require.Contains(t, err.Error(), "domain linkage credential(s) not found")
	})

	t.Run("error - unmarshal error", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte("invalid-json"), testDID, testDomain,
			WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))))
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"JSON unmarshalling of DID configuration bytes failed: invalid character")
	})

	t.Run("error - extra property", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedDataExtraProperty), testDID, testDomain,
			WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))))
		require.Error(t, err)
		require.Contains(t, err.Error(), "key 'extra' is not allowed")
	})

	t.Run("error - did configuration missing context", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedDataNoContext), testDID, testDomain,
			WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))))
		require.Error(t, err)
		require.Contains(t, err.Error(), "key '@context' is required")
	})

	t.Run("error - did configuration missing linked DIDs", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedDataNoLinkedDIDs), testDID, testDomain,
			WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))))
		require.Error(t, err)
		require.Contains(t, err.Error(), "key 'linked_dids' is required")
	})

	t.Run("error - unexpected interface for linked DIDs", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedDataInvalidLinkedDIDs), testDID, testDomain,
			WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))))
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"unexpected interface[float64] for linked DID")
	})

	t.Run("error - invalid VC", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedDataInvalidVC), testDID, testDomain,
			WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))))
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"domain linkage credential(s) not found")
	})
}

func TestParseValidJWT(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader(ldcontext.Document{
		URL:     "https://identity.foundation/.well-known/did-configuration/v1",
		Content: json.RawMessage(didConfigCtx),
	})
	require.NoError(t, err)

	t.Run("success - default options", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgJWT),
			testDID, "identity.foundation")
		require.NoError(t, err)
	})

	t.Run("success - options provided", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgJWT),
			testDID, "identity.foundation",
			WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)
	})
}

func TestIsValidDomainLinkageCredential(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader(ldcontext.Document{
		URL:     ContextV1,
		Content: json.RawMessage(didConfigCtx),
	})
	require.NoError(t, err)

	var credOpts []verifiable.CredentialOpt

	credOpts = append(credOpts,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithNoCustomSchemaCheck(),
		verifiable.WithJSONLDDocumentLoader(loader),
		verifiable.WithStrictValidation())

	t.Run("success", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlc), credOpts...)
		require.NoError(t, err)

		err = isValidDomainLinkageCredential(vc, testDID, testDomain)
		require.NoError(t, err)
	})

	t.Run("error - different DID", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlc), credOpts...)
		require.NoError(t, err)

		err = isValidDomainLinkageCredential(vc, "did:method:id", testDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"credential subject ID[did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM] is different from requested did[did:method:id]") //nolint:lll
	})

	t.Run("error - different domain", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlc), credOpts...)
		require.NoError(t, err)

		err = isValidDomainLinkageCredential(vc, testDID, "https://different.com")
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"origin[https://identity.foundation] and domain origin[https://different.com] are different")
	})

	t.Run("error - credential is not of DomainLinkageCredential type", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlc), credOpts...)
		require.NoError(t, err)

		vc.Types = nil

		err = isValidDomainLinkageCredential(vc, testDID, testDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential is not of DomainLinkageCredential type")
	})

	t.Run("error - credential has ID", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlc), credOpts...)
		require.NoError(t, err)

		vc.ID = "https://domain.com/vc-id"

		err = isValidDomainLinkageCredential(vc, testDID, testDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "id MUST NOT be present")
	})

	t.Run("error - no issuance date", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlc), credOpts...)
		require.NoError(t, err)

		vc.Issued = nil

		err = isValidDomainLinkageCredential(vc, testDID, testDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuance date MUST be present")
	})

	t.Run("error - no expiration date", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlc), credOpts...)
		require.NoError(t, err)

		vc.Expired = nil

		err = isValidDomainLinkageCredential(vc, testDID, testDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expiration date MUST be present")
	})

	t.Run("error - no subject", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlc), credOpts...)
		require.NoError(t, err)

		vc.Subject = nil

		err = isValidDomainLinkageCredential(vc, testDID, testDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "subject MUST be present")
	})

	t.Run("error - no subject origin ", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlc), credOpts...)
		require.NoError(t, err)

		delete(vc.Subject.([]verifiable.Subject)[0].CustomFields, "origin")

		err = isValidDomainLinkageCredential(vc, testDID, testDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSubject.origin MUST be present")
	})

	t.Run("error - subject origin must be a string", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlc), credOpts...)
		require.NoError(t, err)

		vc.Subject.([]verifiable.Subject)[0].CustomFields["origin"] = nil

		err = isValidDomainLinkageCredential(vc, testDID, testDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSubject.origin MUST be string")
	})

	t.Run("error - multiple subjects", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlc), credOpts...)
		require.NoError(t, err)

		vc.Subject = append(vc.Subject.([]verifiable.Subject), vc.Subject.([]verifiable.Subject)[0])

		err = isValidDomainLinkageCredential(vc, testDID, testDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "encountered multiple subjects")
	})

	t.Run("error - unexpected interface for subject", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlc), credOpts...)
		require.NoError(t, err)

		vc.Subject = make(map[string]string)

		err = isValidDomainLinkageCredential(vc, testDID, testDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected interface[map[string]string] for subject")
	})

	t.Run("error - no subject ID", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlc), credOpts...)
		require.NoError(t, err)

		vc.Subject.([]verifiable.Subject)[0].ID = ""

		err = isValidDomainLinkageCredential(vc, testDID, testDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSubject.id MUST be present")
	})

	t.Run("error - subject ID is not DID", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlc), credOpts...)
		require.NoError(t, err)

		vc.Subject.([]verifiable.Subject)[0].ID = "not-did"

		err = isValidDomainLinkageCredential(vc, testDID, testDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "credentialSubject.id MUST be a DID")
	})
}

// nolint: lll,gochecknoglobals
var didCfgLinkedData = `
{
  "@context": "https://identity.foundation/.well-known/did-configuration/v1",
  "linked_dids": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://identity.foundation/.well-known/did-configuration/v1"
      ],
      "issuer": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
      "issuanceDate": "2020-12-04T14:08:28-06:00",
      "expirationDate": "2025-12-04T14:08:28-06:00",
      "type": [
        "VerifiableCredential",
        "DomainLinkageCredential"
      ],
      "credentialSubject": {
        "id": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
        "origin": "https://identity.foundation"
      },
      "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-12-04T20:08:28.540Z",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..D0eDhglCMEjxDV9f_SNxsuU-r3ZB9GR4vaM9TYbyV7yzs1WfdUyYO8rFZdedHbwQafYy8YOpJ1iJlkSmB4JaDQ",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM"
      }
    }
  ]
}`

// nolint: lll,gochecknoglobals
var didCfgLinkedDataInvalidProof = `
{
  "@context": "https://identity.foundation/.well-known/did-configuration/v1",
  "linked_dids": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://identity.foundation/.well-known/did-configuration/v1"
      ],
      "issuer": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
      "issuanceDate": "2020-12-04T14:08:28-06:00",
      "expirationDate": "2025-12-04T14:08:28-06:00",
      "type": [
        "VerifiableCredential",
        "DomainLinkageCredential"
      ],
      "credentialSubject": {
        "id": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
        "origin": "https://identity.foundation"
      },
      "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-12-04T20:08:28.540Z",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..D0eDhglCMEjxDV9f_SNxsuU-r3ZB9GR4vaM9TYbyV7yzs1WfdUyYO8rFZdedHbwQafYy8YOpJ1iJlkSmB4JaDQ",
        "proofPurpose": "assertionMethod"
      }
    }
  ]
}`

// nolint: lll,gochecknoglobals
var didCfgLinkedDataInvalidVC = `
{
  "@context": "https://identity.foundation/.well-known/did-configuration/v1",
  "linked_dids": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://identity.foundation/.well-known/did-configuration/v1"
      ],
      "issuer": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
      "expirationDate": "2025-12-04T14:08:28-06:00",
      "type": [
        "VerifiableCredential",
        "DomainLinkageCredential"
      ],
      "credentialSubject": {
        "id": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
        "origin": "https://identity.foundation"
      },
      "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-12-04T20:08:28.540Z",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..D0eDhglCMEjxDV9f_SNxsuU-r3ZB9GR4vaM9TYbyV7yzs1WfdUyYO8rFZdedHbwQafYy8YOpJ1iJlkSmB4JaDQ",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM"
      }
    }
  ]
}`

// nolint: lll,gochecknoglobals
var didCfgLinkedDataExtraProperty = `
{
  "extra": "value",
  "@context": "https://identity.foundation/.well-known/did-configuration/v1",
  "linked_dids": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://identity.foundation/.well-known/did-configuration/v1"
      ],
      "issuer": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
      "issuanceDate": "2020-12-04T14:08:28-06:00",
      "expirationDate": "2025-12-04T14:08:28-06:00",
      "type": [
        "VerifiableCredential",
        "DomainLinkageCredential"
      ],
      "credentialSubject": {
        "id": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
        "origin": "https://identity.foundation"
      },
      "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-12-04T20:08:28.540Z",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..D0eDhglCMEjxDV9f_SNxsuU-r3ZB9GR4vaM9TYbyV7yzs1WfdUyYO8rFZdedHbwQafYy8YOpJ1iJlkSmB4JaDQ",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM"
      }
    }
  ]
}`

// nolint: gochecknoglobals
var didCfgLinkedDataNoLinkedDIDs = `
{
  "@context": "https://identity.foundation/.well-known/did-configuration/v1"
}`

// nolint: lll,gochecknoglobals
var didCfgLinkedDataNoContext = `
{
  "linked_dids": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://identity.foundation/.well-known/did-configuration/v1"
      ],
      "issuer": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
      "issuanceDate": "2020-12-04T14:08:28-06:00",
      "expirationDate": "2025-12-04T14:08:28-06:00",
      "type": [
        "VerifiableCredential",
        "DomainLinkageCredential"
      ],
      "credentialSubject": {
        "id": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
        "origin": "https://identity.foundation"
      },
      "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-12-04T20:08:28.540Z",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..D0eDhglCMEjxDV9f_SNxsuU-r3ZB9GR4vaM9TYbyV7yzs1WfdUyYO8rFZdedHbwQafYy8YOpJ1iJlkSmB4JaDQ",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM"
      }
    }
  ]
}`

// nolint: gochecknoglobals
var didCfgLinkedDataInvalidLinkedDIDs = `
{
  "@context": "https://identity.foundation/.well-known/did-configuration/v1",
  "linked_dids": [ 1, 2 ]
}`

// nolint: lll,gochecknoglobals
var dlc = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://identity.foundation/.well-known/did-configuration/v1"
  ],
  "issuer": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
  "issuanceDate": "2020-12-04T14:08:28-06:00",
  "expirationDate": "2025-12-04T14:08:28-06:00",
  "type": [
    "VerifiableCredential",
    "DomainLinkageCredential"
  ],
  "credentialSubject": {
    "id": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
    "origin": "https://identity.foundation"
  },
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2020-12-04T20:08:28.540Z",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..D0eDhglCMEjxDV9f_SNxsuU-r3ZB9GR4vaM9TYbyV7yzs1WfdUyYO8rFZdedHbwQafYy8YOpJ1iJlkSmB4JaDQ",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM"
  }
}`

// nolint: lll,gochecknoglobals
var didCfgJWT = `
{
  "@context": "https://identity.foundation/.well-known/did-configuration/v1",
  "linked_dids": [
    "eyJhbGciOiJFZERTQSJ9.eyJleHAiOjE3NjQ4Nzg5MDgsImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNTA4LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJpZGVudGl0eS5mb3VuZGF0aW9uIn0sImV4cGlyYXRpb25EYXRlIjoiMjAyNS0xMi0wNFQxNDowODoyOC0wNjowMCIsImlzc3VhbmNlRGF0ZSI6IjIwMjAtMTItMDRUMTQ6MDg6MjgtMDY6MDAiLCJpc3N1ZXIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJEb21haW5MaW5rYWdlQ3JlZGVudGlhbCJdfX0.6ovgQ-T_rmYueviySqXhzMzgqJMAizOGUKAObQr2iikoRNsb8DHfna4rh1puwWqYwgT3QJVpzdO_xZARAYM9Dw"
  ]
}`

// nolint: lll,gochecknoglobals
var didConfigCtx = `
{
  "@context": [
    {
      "@version": 1.1,
      "@protected": true,
      "LinkedDomains": "https://identity.foundation/.well-known/resources/did-configuration/#LinkedDomains",
      "DomainLinkageCredential": "https://identity.foundation/.well-known/resources/did-configuration/#DomainLinkageCredential",
      "origin": "https://identity.foundation/.well-known/resources/did-configuration/#origin",
      "linked_dids": "https://identity.foundation/.well-known/resources/did-configuration/#linked_dids"
    }
  ]
}`
