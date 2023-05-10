/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/api"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/keyio"
	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	resolver "github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/kidresolver"
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

// Decrypter interface to Decrypt JWE messages.
type Decrypter interface {
	// Decrypt a deserialized JWE, extracts the corresponding recipient key to decrypt plaintext and returns it
	Decrypt(jwe *JSONWebEncryption) ([]byte, error)
}

// JWEDecrypt is responsible for decrypting a JWE message and returns its protected plaintext.
type JWEDecrypt struct {
	kidResolvers []resolver.KIDResolver
	crypto       cryptoapi.Crypto
	kms          kms.KeyManager
}

// NewJWEDecrypt creates a new JWEDecrypt instance to parse and decrypt a JWE message for a given recipient
// store is needed for Authcrypt only (to fetch sender's pre agreed upon public key), it is not needed for Anoncrypt.
func NewJWEDecrypt(kidResolvers []resolver.KIDResolver, c cryptoapi.Crypto, k kms.KeyManager) *JWEDecrypt {
	return &JWEDecrypt{
		kidResolvers: kidResolvers,
		crypto:       c,
		kms:          k,
	}
}

func getECDHDecPrimitive(cek []byte, encAlg EncAlg, nistpKW bool) (api.CompositeDecrypt, error) {
	ceAlg := aeadAlg[encAlg]

	if ceAlg <= 0 {
		return nil, fmt.Errorf("invalid content encAlg: '%s'", encAlg)
	}

	kt := ecdh.KeyTemplateForECDHPrimitiveWithCEK(cek, nistpKW, ceAlg)

	kh, err := keyset.NewHandle(kt)
	if err != nil {
		return nil, err
	}

	return ecdh.NewECDHDecrypt(kh)
}

// Decrypt a deserialized JWE, decrypts its protected content and returns plaintext.
func (jd *JWEDecrypt) Decrypt(jwe *JSONWebEncryption) ([]byte, error) {
	encAlg, err := jd.validateAndExtractProtectedHeaders(jwe)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: %w", err)
	}

	var wkOpts []cryptoapi.WrapKeyOpts

	skid, ok := jwe.ProtectedHeaders.SenderKeyID()
	if !ok {
		skid, ok = fetchSKIDFromAPU(jwe)
	}

	if ok && skid != "" {
		senderKH, e := jd.fetchSenderPubKey(skid, EncAlg(encAlg))
		if e != nil {
			return nil, fmt.Errorf("jwedecrypt: failed to add sender public key for skid: %w", e)
		}

		wkOpts = append(wkOpts, cryptoapi.WithSender(senderKH), cryptoapi.WithTag([]byte(jwe.Tag)))
	}

	recWK, err := buildRecipientsWrappedKey(jwe)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: failed to build recipients WK: %w", err)
	}

	cek, err := jd.unwrapCEK(recWK, wkOpts...)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: %w", err)
	}

	if len(recWK) == 1 {
		// ensure EPK is marshalled the same way as during encryption since it is merged into ProtectHeaders.
		marshalledEPK, err := convertRecEPKToMarshalledJWK(&recWK[0].EPK)
		if err != nil {
			return nil, fmt.Errorf("jwedecrypt: %w", err)
		}

		jwe.ProtectedHeaders["epk"] = json.RawMessage(marshalledEPK)
	}

	return jd.decryptJWE(jwe, cek)
}

func fetchSKIDFromAPU(jwe *JSONWebEncryption) (string, bool) {
	// for multi-recipients only: check apu in protectedHeaders if it's found for ECDH-1PU, if skid header is empty then
	// use apu as skid instead.
	if len(jwe.Recipients) > 1 {
		if a, apuOK := jwe.ProtectedHeaders["apu"]; apuOK {
			skidBytes, err := base64.RawURLEncoding.DecodeString(a.(string))
			if err != nil {
				return "", false
			}

			return string(skidBytes), true
		}
	}

	return "", false
}

//nolint:gocyclo
func (jd *JWEDecrypt) unwrapCEK(recWK []*cryptoapi.RecipientWrappedKey,
	senderOpt ...cryptoapi.WrapKeyOpts) ([]byte, error) {
	var (
		cek  []byte
		errs []error
	)

	for _, rec := range recWK {
		var unwrapOpts []cryptoapi.WrapKeyOpts

		if strings.HasPrefix(rec.KID, "did:key") || strings.Index(rec.KID, "#") > 0 {
			// resolve and use kms KID if did:key or KeyAgreement.ID.
			resolvedRec, err := jd.resolveKID(rec.KID)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			// Need to get the kms KID in order to do kms.Get() since original rec.KID is a did:key/KeyAgreement.ID.
			// This is necessary to ensure recipient is the owner of the key.
			rec.KID = resolvedRec.KID
		}

		recKH, err := jd.kms.Get(rec.KID)
		if err != nil {
			continue
		}

		if rec.EPK.Type == ecdhpb.KeyType_OKP.String() {
			unwrapOpts = append(unwrapOpts, cryptoapi.WithXC20PKW())
		}

		if senderOpt != nil {
			unwrapOpts = append(unwrapOpts, senderOpt...)
		}

		if len(unwrapOpts) > 0 {
			cek, err = jd.crypto.UnwrapKey(rec, recKH, unwrapOpts...)
		} else {
			cek, err = jd.crypto.UnwrapKey(rec, recKH)
		}

		if err == nil {
			break
		}

		errs = append(errs, err)
	}

	if len(cek) == 0 {
		return nil, fmt.Errorf("failed to unwrap cek: %v", errs)
	}

	return cek, nil
}

func (jd *JWEDecrypt) resolveKID(kid string) (*cryptoapi.PublicKey, error) {
	var errs []error

	for _, resolver := range jd.kidResolvers {
		rKID, err := resolver.Resolve(kid)
		if err == nil {
			return rKID, nil
		}

		errs = append(errs, err)
	}

	return nil, fmt.Errorf("resolveKID: %v", errs)
}

func (jd *JWEDecrypt) decryptJWE(jwe *JSONWebEncryption, cek []byte) ([]byte, error) {
	encAlg, ok := jwe.ProtectedHeaders.Encryption()
	if !ok {
		return nil, fmt.Errorf("jwedecrypt: JWE 'enc' protected header is missing")
	}

	decPrimitive, err := getECDHDecPrimitive(cek, EncAlg(encAlg), true)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: failed to get decryption primitive: %w", err)
	}

	encryptedData, err := buildEncryptedData(jwe)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: failed to build encryptedData for Decrypt(): %w", err)
	}

	aadBytes := []byte(jwe.AAD)

	authData, err := computeAuthData(jwe.ProtectedHeaders, jwe.OrigProtectedHders, aadBytes)
	if err != nil {
		return nil, err
	}

	return decPrimitive.Decrypt(encryptedData, authData)
}

func (jd *JWEDecrypt) fetchSenderPubKey(skid string, encAlg EncAlg) (*keyset.Handle, error) {
	senderKey, err := jd.resolveKID(skid)
	if err != nil {
		return nil, fmt.Errorf("fetchSenderPubKey: %w", err)
	}

	ceAlg := aeadAlg[encAlg]

	if ceAlg <= 0 {
		return nil, fmt.Errorf("fetchSenderPubKey: invalid content encAlg: '%s'", encAlg)
	}

	return keyio.PublicKeyToKeysetHandle(senderKey, ceAlg)
}

func (jd *JWEDecrypt) validateAndExtractProtectedHeaders(jwe *JSONWebEncryption) (string, error) {
	if jwe == nil {
		return "", fmt.Errorf("jwe is nil")
	}

	if len(jwe.ProtectedHeaders) == 0 {
		return "", fmt.Errorf("jwe is missing protected headers")
	}

	protectedHeaders := jwe.ProtectedHeaders

	encAlg, ok := protectedHeaders.Encryption()
	if !ok {
		return "", fmt.Errorf("jwe is missing encryption algorithm 'enc' header")
	}

	switch encAlg {
	case string(A256GCM), string(XC20P), string(A128CBCHS256),
		string(A192CBCHS384), string(A256CBCHS384), string(A256CBCHS512):
	default:
		return "", fmt.Errorf("encryption algorithm '%s' not supported", encAlg)
	}

	return encAlg, nil
}

func buildRecipientsWrappedKey(jwe *JSONWebEncryption) ([]*cryptoapi.RecipientWrappedKey, error) {
	var (
		recipients []*cryptoapi.RecipientWrappedKey
		err        error
	)

	for _, recJWE := range jwe.Recipients {
		headers := recJWE.Header
		alg, ok := jwe.ProtectedHeaders.Algorithm()
		is1PU := ok && strings.Contains(strings.ToUpper(alg), "1PU")

		if len(jwe.Recipients) == 1 || is1PU {
			// compact serialization: it has only 1 recipient with no headers or 1pu, extract from protectedHeaders.
			headers, err = extractRecipientHeaders(jwe.ProtectedHeaders)
			if err != nil {
				return nil, err
			}
		}

		var recWK *cryptoapi.RecipientWrappedKey
		// set kid if 1PU (authcrypt) with multi recipients since common protected headers don't have the recipient kid.
		if is1PU && len(jwe.Recipients) > 1 {
			headers.KID = recJWE.Header.KID
		}

		recWK, err = createRecWK(headers, []byte(recJWE.EncryptedKey))
		if err != nil {
			return nil, err
		}

		recipients = append(recipients, recWK)
	}

	return recipients, nil
}

func createRecWK(headers *RecipientHeaders, encryptedKey []byte) (*cryptoapi.RecipientWrappedKey, error) {
	recWK, err := convertMarshalledJWKToRecKey(headers.EPK)
	if err != nil {
		return nil, err
	}

	recWK.KID = headers.KID
	recWK.Alg = headers.Alg

	err = updateAPUAPVInRecWK(recWK, headers)
	if err != nil {
		return nil, err
	}

	recWK.EncryptedCEK = encryptedKey

	return recWK, nil
}

func updateAPUAPVInRecWK(recWK *cryptoapi.RecipientWrappedKey, headers *RecipientHeaders) error {
	decodedAPU, decodedAPV, err := decodeAPUAPV(headers)
	if err != nil {
		return fmt.Errorf("updateAPUAPVInRecWK: %w", err)
	}

	recWK.APU = decodedAPU
	recWK.APV = decodedAPV

	return nil
}

func buildEncryptedData(jwe *JSONWebEncryption) ([]byte, error) {
	encData := new(composite.EncryptedData)
	encData.Tag = []byte(jwe.Tag)
	encData.IV = []byte(jwe.IV)
	encData.Ciphertext = []byte(jwe.Ciphertext)

	return json.Marshal(encData)
}

// extractRecipientHeaders will extract RecipientHeaders from headers argument.
func extractRecipientHeaders(headers map[string]interface{}) (*RecipientHeaders, error) {
	// Since headers is a generic map, epk value is converted to a generic map by Serialize(), ie we lose RawMessage
	// type of epk. We need to convert epk value (generic map) to marshaled json so we can call RawMessage.Unmarshal()
	// to get the original epk value (RawMessage type).
	mapData, ok := headers[HeaderEPK].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("JSON value is not a map (%#v)", headers[HeaderEPK])
	}

	epkBytes, err := json.Marshal(mapData)
	if err != nil {
		return nil, err
	}

	epk := json.RawMessage{}

	err = epk.UnmarshalJSON(epkBytes)
	if err != nil {
		return nil, err
	}

	alg := ""
	if headers[HeaderAlgorithm] != nil {
		alg = fmt.Sprintf("%v", headers[HeaderAlgorithm])
	}

	kid := ""
	if headers[HeaderKeyID] != nil {
		kid = fmt.Sprintf("%v", headers[HeaderKeyID])
	}

	apu := ""
	if headers["apu"] != nil {
		apu = fmt.Sprintf("%v", headers["apu"])
	}

	apv := ""
	if headers["apv"] != nil {
		apv = fmt.Sprintf("%v", headers["apv"])
	}

	recHeaders := &RecipientHeaders{
		Alg: alg,
		KID: kid,
		EPK: epk,
		APU: apu,
		APV: apv,
	}

	// original headers should remain untouched to avoid modifying the original JWE content.
	return recHeaders, nil
}

func convertMarshalledJWKToRecKey(marshalledJWK []byte) (*cryptoapi.RecipientWrappedKey, error) {
	j := &jwk.JWK{}

	err := j.UnmarshalJSON(marshalledJWK)
	if err != nil {
		return nil, err
	}

	epk := cryptoapi.PublicKey{
		Curve: j.Crv,
		Type:  j.Kty,
	}

	switch key := j.Key.(type) {
	case *ecdsa.PublicKey:
		epk.X = key.X.Bytes()
		epk.Y = key.Y.Bytes()
	case []byte:
		epk.X = key
	default:
		return nil, fmt.Errorf("unsupported recipient key type")
	}

	return &cryptoapi.RecipientWrappedKey{
		KID: j.KeyID,
		EPK: epk,
	}, nil
}
