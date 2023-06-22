/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
	ldtestutil "github.com/hyperledger/aries-framework-go/component/models/ld/testutil"
	sigutil "github.com/hyperledger/aries-framework-go/component/models/signature/util"
	afgotime "github.com/hyperledger/aries-framework-go/component/models/util/time"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	"github.com/hyperledger/aries-framework-go/component/vdr"
	"github.com/hyperledger/aries-framework-go/component/vdr/key"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

const (
	testDID       = "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM"
	testDomain    = "https://identity.foundation"
	testJWTDomain = "identity.foundation"

	testKID = "76e12ec712ebc6f1c221ebfeb1f"
)

func TestParseOfNull(t *testing.T) {
	err := VerifyDIDAndDomain([]byte("null"), testDID, testDomain)
	require.Error(t, err)
	require.Contains(t, err.Error(), "DID configuration payload is not provided")
}

func TestParseLinkedData(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader(ldcontext.Document{
		URL:     ContextV1,
		Content: json.RawMessage(didCfgCtxV1),
	})
	require.NoError(t, err)

	/* This test is accessing remote URL, and it is often failing in CI.
	t.Run("success - default options", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedData), testDID, testDomain)
		require.NoError(t, err)
	})
	*/

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
		require.Contains(t, err.Error(), "property 'extra' is not allowed")
	})

	t.Run("error - did configuration missing context", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedDataNoContext), testDID, testDomain,
			WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))))
		require.Error(t, err)
		require.Contains(t, err.Error(), "property '@context' is required")
	})

	t.Run("error - did configuration missing linked DIDs", func(t *testing.T) {
		err := VerifyDIDAndDomain([]byte(didCfgLinkedDataNoLinkedDIDs), testDID, testDomain,
			WithJSONLDDocumentLoader(loader),
			WithVDRegistry(vdr.New(vdr.WithVDR(key.New()))))
		require.Error(t, err)
		require.Contains(t, err.Error(), "property 'linked_dids' is required")
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
		Content: json.RawMessage(didCfgCtxV1),
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

func TestIsValidDomainCredentialJWT(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader(ldcontext.Document{
		URL:     ContextV1,
		Content: json.RawMessage(didCfgCtxV1),
	})
	require.NoError(t, err)

	var credOpts []verifiable.CredentialOpt

	credOpts = append(credOpts,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithNoCustomSchemaCheck(),
		verifiable.WithJSONLDDocumentLoader(loader),
		verifiable.WithStrictValidation())

	t.Run("success", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlcJWT), credOpts...)
		require.NoError(t, err)

		err = isValidDomainLinkageCredential(vc, testDID, testJWTDomain)
		require.NoError(t, err)
	})

	t.Run("success - credential created with AFG", func(t *testing.T) {
		dlcJWT := &verifiable.Credential{
			Issued:  afgotime.NewTime(time.Now()),
			Expired: afgotime.NewTime(time.Now().Add(time.Hour)),
			Context: []string{verifiable.ContextURI, ContextV1},
			Types:   []string{verifiable.VCType, domainLinkageCredentialType},
			Subject: []verifiable.Subject{{ID: testDID, CustomFields: map[string]interface{}{"origin": testJWTDomain}}},
			Issuer:  verifiable.Issuer{ID: testDID},
		}

		ed25519Signer, err := newCryptoSigner(kms.ED25519Type)
		require.NoError(t, err)

		dlcJWT.JWT = createEdDSAJWS(t, dlcJWT, ed25519Signer, testKID, false)

		jwt, err := dlcJWT.MarshalJSON()
		require.NoError(t, err)

		vcParsed, err := verifiable.ParseCredential(jwt, credOpts...)
		require.NoError(t, err)

		err = isValidDomainLinkageCredential(vcParsed, testDID, testJWTDomain)
		require.NoError(t, err)
	})

	t.Run("success - type JWT in header", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlcJWTWithType), credOpts...)
		require.NoError(t, err)

		err = isValidDomainLinkageCredential(vc, testDID, testJWTDomain)
		require.NoError(t, err)
	})

	t.Run("success - iat property allowed in payload", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlcJWTWithIAT), credOpts...)
		require.NoError(t, err)

		err = isValidDomainLinkageCredential(vc, testDID, testJWTDomain)
		require.NoError(t, err)
	})

	t.Run("error - typ not JWT", func(t *testing.T) {
		dlcJWT := &verifiable.Credential{
			Issued:  afgotime.NewTime(time.Now()),
			Expired: afgotime.NewTime(time.Now().Add(time.Hour)),
			Context: []string{verifiable.ContextURI, ContextV1},
			Types:   []string{verifiable.VCType, domainLinkageCredentialType},
			Subject: []verifiable.Subject{{ID: testDID, CustomFields: map[string]interface{}{"origin": testJWTDomain}}},
			Issuer:  verifiable.Issuer{ID: testDID},
		}

		jwtClaims, err := dlcJWT.JWTClaims(false)
		require.NoError(t, err)

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		headers := map[string]interface{}{
			jose.HeaderKeyID: testKID,
		}

		token, err := afgjwt.NewSigned(jwtClaims, headers, afgjwt.NewEd25519Signer(privKey))
		require.NoError(t, err)

		jwt, err := token.Serialize(false)
		require.NoError(t, err)

		vcParsed, err := verifiable.ParseCredential([]byte("\""+jwt+"\""), credOpts...)
		require.NoError(t, err)

		headers["typ"] = "whatever"

		token, err = afgjwt.NewSigned(jwtClaims, headers, afgjwt.NewEd25519Signer(privKey))
		require.NoError(t, err)

		jwt, err = token.Serialize(false)
		require.NoError(t, err)

		vcParsed.JWT = jwt

		err = isValidDomainLinkageCredential(vcParsed, testDID, testJWTDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse JWT: check JWT headers: typ is not JWT")
	})

	t.Run("error - no alg in JWT header", func(t *testing.T) {
		dlcJWT := &verifiable.Credential{
			Issued:  afgotime.NewTime(time.Now()),
			Expired: afgotime.NewTime(time.Now().Add(time.Hour)),
			Context: []string{verifiable.ContextURI, ContextV1},
			Types:   []string{verifiable.VCType, domainLinkageCredentialType},
			Subject: []verifiable.Subject{{ID: testDID, CustomFields: map[string]interface{}{"origin": testJWTDomain}}},
			Issuer:  verifiable.Issuer{ID: testDID},
		}

		jwtClaims, err := dlcJWT.JWTClaims(false)
		require.NoError(t, err)

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		headers := map[string]interface{}{
			jose.HeaderKeyID: testKID,
		}

		token, err := afgjwt.NewSigned(jwtClaims, headers, afgjwt.NewEd25519Signer(privKey))
		require.NoError(t, err)

		jwt, err := token.Serialize(false)
		require.NoError(t, err)

		vcParsed, err := verifiable.ParseCredential([]byte("\""+jwt+"\""), credOpts...)
		require.NoError(t, err)

		headers["alg"] = nil

		token, err = afgjwt.NewSigned(jwtClaims, headers, afgjwt.NewEd25519Signer(privKey))
		require.NoError(t, err)

		jwt, err = token.Serialize(false)
		require.NoError(t, err)

		vcParsed.JWT = jwt

		err = isValidDomainLinkageCredential(vcParsed, testDID, testJWTDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "alg MUST be present in the JWT Header")
	})

	t.Run("error - extra property in JWT Payload", func(t *testing.T) {
		dlcJWT := &verifiable.Credential{
			Issued:  afgotime.NewTime(time.Now()),
			Expired: afgotime.NewTime(time.Now().Add(time.Hour)),
			Context: []string{verifiable.ContextURI, ContextV1},
			Types:   []string{verifiable.VCType, domainLinkageCredentialType},
			Subject: []verifiable.Subject{{ID: testDID, CustomFields: map[string]interface{}{"origin": testJWTDomain}}},
			Issuer:  verifiable.Issuer{ID: testDID},
		}

		jwtClaims, err := dlcJWT.JWTClaims(false)
		require.NoError(t, err)

		jwtClaims.ID = "https://domain.com"

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		headers := map[string]interface{}{
			jose.HeaderKeyID: testKID,
		}

		token, err := afgjwt.NewSigned(jwtClaims, headers, afgjwt.NewEd25519Signer(privKey))
		require.NoError(t, err)

		jwt, err := token.Serialize(false)
		require.NoError(t, err)

		vcParsed, err := verifiable.ParseCredential([]byte("\""+jwt+"\""), credOpts...)
		require.NoError(t, err)

		err = isValidDomainLinkageCredential(vcParsed, testDID, testJWTDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWT Payload: property 'jti' is not allowed")
	})

	t.Run("error - extra property in JWT Header", func(t *testing.T) {
		dlcJWT := &verifiable.Credential{
			Issued:  afgotime.NewTime(time.Now()),
			Expired: afgotime.NewTime(time.Now().Add(time.Hour)),
			Context: []string{verifiable.ContextURI, ContextV1},
			Types:   []string{verifiable.VCType, domainLinkageCredentialType},
			Subject: []verifiable.Subject{{ID: testDID, CustomFields: map[string]interface{}{"origin": testJWTDomain}}},
			Issuer:  verifiable.Issuer{ID: testDID},
		}

		jwtClaims, err := dlcJWT.JWTClaims(false)
		require.NoError(t, err)

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		headers := map[string]interface{}{
			jose.HeaderKeyID: testKID,
			"extra":          "value",
		}

		token, err := afgjwt.NewSigned(jwtClaims, headers, afgjwt.NewEd25519Signer(privKey))
		require.NoError(t, err)

		jwt, err := token.Serialize(false)
		require.NoError(t, err)

		vcParsed, err := verifiable.ParseCredential([]byte("\""+jwt+"\""), credOpts...)
		require.NoError(t, err)

		err = isValidDomainLinkageCredential(vcParsed, testDID, testJWTDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWT Header: property 'extra' is not allowed")
	})

	t.Run("error - different DID", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlcJWT), credOpts...)
		require.NoError(t, err)

		err = isValidDomainLinkageCredential(vc, "did:method:id", testJWTDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"iss MUST be equal to credentialSubject.id")
	})

	t.Run("error - different domain", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlcJWT), credOpts...)
		require.NoError(t, err)

		err = isValidDomainLinkageCredential(vc, testDID, "https://different.com")
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"origin[identity.foundation] and domain origin[https://different.com] are different")
	})

	t.Run("error - no KID in header", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlcJWTNoKID), credOpts...)
		require.NoError(t, err)

		err = isValidDomainLinkageCredential(vc, testDID, testJWTDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"kid MUST be present in the JWT Header")
	})

	t.Run("error - invalid JWT", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(dlcJWT), credOpts...)
		require.NoError(t, err)

		vc.JWT = "invalid.abc.xyz"

		err = isValidDomainLinkageCredential(vc, testDID, testJWTDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse JWT: parse JWT from compact JWS: unmarshal JSON headers")
	})

	t.Run("error - sub must be equal to subject ID", func(t *testing.T) {
		dlcJWT := &verifiable.Credential{
			Issued:  afgotime.NewTime(time.Now()),
			Expired: afgotime.NewTime(time.Now().Add(time.Hour)),
			Context: []string{verifiable.ContextURI, ContextV1},
			Types:   []string{verifiable.VCType, domainLinkageCredentialType},
			Subject: []verifiable.Subject{{ID: "did:key:different", CustomFields: map[string]interface{}{"origin": testJWTDomain}}}, // nolint:lll
			Issuer:  verifiable.Issuer{ID: testDID},
		}

		ed25519Signer, err := newCryptoSigner(kms.ED25519Type)
		require.NoError(t, err)

		dlcJWT.JWT = createEdDSAJWS(t, dlcJWT, ed25519Signer, testKID, false)

		err = isValidDomainLinkageCredential(dlcJWT, testDID, testJWTDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"sub MUST be equal to credentialSubject.id")
	})

	t.Run("error - create JWT Claims error", func(t *testing.T) {
		dlcJWT := &verifiable.Credential{
			Issued:  afgotime.NewTime(time.Now()),
			Expired: afgotime.NewTime(time.Now().Add(time.Hour)),
			Context: []string{verifiable.ContextURI, ContextV1},
			Types:   []string{verifiable.VCType, domainLinkageCredentialType},
			Subject: []verifiable.Subject{{ID: testDID, CustomFields: map[string]interface{}{"origin": testJWTDomain}}},
			Issuer:  verifiable.Issuer{ID: testDID},
		}

		ed25519Signer, err := newCryptoSigner(kms.ED25519Type)
		require.NoError(t, err)

		dlcJWT.JWT = createEdDSAJWS(t, dlcJWT, ed25519Signer, testKID, false)

		dlcJWT.Subject = nil

		err = isValidDomainLinkageCredential(dlcJWT, testDID, testJWTDomain)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get VC subject id: subject id is not defined")
	})
}

func TestIsValidDomainLinkageCredential(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader(ldcontext.Document{
		URL:     ContextV1,
		Content: json.RawMessage(didCfgCtxV1),
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
			"credential subject ID[did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM] is different from requested DID[did:method:id]") //nolint:lll
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

func createEdDSAJWS(t *testing.T, cred *verifiable.Credential, signer verifiable.Signer,
	keyID string, minimize bool) string {
	t.Helper()

	jwtClaims, err := cred.JWTClaims(minimize)
	require.NoError(t, err)
	vcJWT, err := jwtClaims.MarshalJWS(verifiable.EdDSA, signer, cred.Issuer.ID+"#keys-"+keyID)
	require.NoError(t, err)

	return vcJWT
}

func createKMS() (*localkms.LocalKMS, error) {
	p, err := mockkms.NewProviderForKMS(storage.NewMockStoreProvider(), &noop.NoLock{})
	if err != nil {
		return nil, err
	}

	return localkms.New("local-lock://custom/master/key/", p)
}

func newCryptoSigner(keyType kms.KeyType) (sigutil.Signer, error) {
	localKMS, err := createKMS()
	if err != nil {
		return nil, err
	}

	tinkCrypto, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	return sigutil.NewCryptoSigner(tinkCrypto, localKMS, keyType)
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
    "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNzM5LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJpZGVudGl0eS5mb3VuZGF0aW9uIn0sImV4cGlyYXRpb25EYXRlIjoiMjAyNS0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VhbmNlRGF0ZSI6IjIwMjAtMTItMDRUMTQ6MTI6MTktMDY6MDAiLCJpc3N1ZXIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJEb21haW5MaW5rYWdlQ3JlZGVudGlhbCJdfX0.aUFNReA4R5rcX_oYm3sPXqWtso_gjPHnWZsB6pWcGv6m3K8-4JIAvFov3ZTM8HxPOrOL17Qf4vBFdY9oK0HeCQ"
  ]
}`

// nolint: lll,gochecknoglobals
var dlcJWTNoKID = "eyJhbGciOiJFZERTQSJ9.eyJleHAiOjE3NjQ4Nzg5MDgsImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNTA4LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJpZGVudGl0eS5mb3VuZGF0aW9uIn0sImV4cGlyYXRpb25EYXRlIjoiMjAyNS0xMi0wNFQxNDowODoyOC0wNjowMCIsImlzc3VhbmNlRGF0ZSI6IjIwMjAtMTItMDRUMTQ6MDg6MjgtMDY6MDAiLCJpc3N1ZXIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJEb21haW5MaW5rYWdlQ3JlZGVudGlhbCJdfX0.6ovgQ-T_rmYueviySqXhzMzgqJMAizOGUKAObQr2iikoRNsb8DHfna4rh1puwWqYwgT3QJVpzdO_xZARAYM9Dw"

// nolint: lll,gochecknoglobals
var dlcJWTWithType = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI2tleXMtNzZlMTJlYzcxMmViYzZmMWMyMjFlYmZlYjFmIiwidHlwIjoiSldUIn0.eyJleHAiOjE2NjM3MTMyMDQsImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjYzNzA5NjA0LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJpZGVudGl0eS5mb3VuZGF0aW9uIn0sImV4cGlyYXRpb25EYXRlIjoiMjAyMi0wOS0yMFQxODozMzoyNC41MTU1NjctMDQ6MDAiLCJpc3N1YW5jZURhdGUiOiIyMDIyLTA5LTIwVDE3OjMzOjI0LjUxNTU2Ny0wNDowMCIsImlzc3VlciI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkRvbWFpbkxpbmthZ2VDcmVkZW50aWFsIl19fQ.don8sfLqK59k7iuCF-xNRfCy8DW3gXi_mKmDkE-t8Hqq0SlxHPEP76I41ATOspRgX0e375UDUNXm_T1akRh9Dg"

// nolint: lll,gochecknoglobals
var dlcJWTWithIAT = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI2tleXMtNzZlMTJlYzcxMmViYzZmMWMyMjFlYmZlYjFmIn0.eyJleHAiOjE2NjM3MTQyNDUsImlhdCI6MTY2MzcxMDY0NSwiaXNzIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJuYmYiOjE2NjM3MTA2NDUsInN1YiI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL2lkZW50aXR5LmZvdW5kYXRpb24vLndlbGwta25vd24vZGlkLWNvbmZpZ3VyYXRpb24vdjEiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsIm9yaWdpbiI6ImlkZW50aXR5LmZvdW5kYXRpb24ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDIyLTA5LTIwVDE4OjUwOjQ1LjExMTg2OC0wNDowMCIsImlzc3VhbmNlRGF0ZSI6IjIwMjItMDktMjBUMTc6NTA6NDUuMTExODY4LTA0OjAwIiwiaXNzdWVyIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXX19.wojEPD3G8NeyJOuwKga8HDRpY3oNEAyDEEPH8OgpPNHU8_g9JARVJPb-4hrIoNtyT_R-2FPqka0oXzTjxqLpCQ"

// nolint: lll,gochecknoglobals
var dlcJWT = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNzM5LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJpZGVudGl0eS5mb3VuZGF0aW9uIn0sImV4cGlyYXRpb25EYXRlIjoiMjAyNS0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VhbmNlRGF0ZSI6IjIwMjAtMTItMDRUMTQ6MTI6MTktMDY6MDAiLCJpc3N1ZXIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJEb21haW5MaW5rYWdlQ3JlZGVudGlhbCJdfX0.aUFNReA4R5rcX_oYm3sPXqWtso_gjPHnWZsB6pWcGv6m3K8-4JIAvFov3ZTM8HxPOrOL17Qf4vBFdY9oK0HeCQ"

// nolint: lll,gochecknoglobals
var didCfgCtxV1 = `
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
