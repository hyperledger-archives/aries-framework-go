/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

const didV1Context = `
{
  "@context": {
    "@version": 1.1,
    "id": "@id",
    "type": "@type",
    "dc": "http://purl.org/dc/terms/",
    "schema": "http://schema.org/",
    "sec": "https://w3id.org/security#",
    "didv": "https://w3id.org/did#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "EcdsaSecp256k1Signature2019": "sec:EcdsaSecp256k1Signature2019",
    "EcdsaSecp256k1VerificationKey2019": "sec:EcdsaSecp256k1VerificationKey2019",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "Ed25519VerificationKey2018": "sec:Ed25519VerificationKey2018",
    "RsaSignature2018": "sec:RsaSignature2018",
    "RsaVerificationKey2018": "sec:RsaVerificationKey2018",
    "SchnorrSecp256k1Signature2019": "sec:SchnorrSecp256k1Signature2019",
    "SchnorrSecp256k1VerificationKey2019": "sec:SchnorrSecp256k1VerificationKey2019",
    "ServiceEndpointProxyService": "didv:ServiceEndpointProxyService",
    "allowedAction": "sec:allowedAction",
    "assertionMethod": {
      "@id": "sec:assertionMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "authentication": {
      "@id": "sec:authenticationMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "capability": {
      "@id": "sec:capability",
      "@type": "@id"
    },
    "capabilityAction": "sec:capabilityAction",
    "capabilityChain": {
      "@id": "sec:capabilityChain",
      "@type": "@id",
      "@container": "@list"
    },
    "capabilityDelegation": {
      "@id": "sec:capabilityDelegationMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "capabilityInvocation": {
      "@id": "sec:capabilityInvocationMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "capabilityStatusList": {
      "@id": "sec:capabilityStatusList",
      "@type": "@id"
    },
    "canonicalizationAlgorithm": "sec:canonicalizationAlgorithm",
    "caveat": {
      "@id": "sec:caveat",
      "@type": "@id",
      "@container": "@set"
    },
    "challenge": "sec:challenge",
    "controller": {
      "@id": "sec:controller",
      "@type": "@id"
    },
    "created": {
      "@id": "dc:created",
      "@type": "xsd:dateTime"
    },
    "creator": {
      "@id": "dc:creator",
      "@type": "@id"
    },
    "delegator": {
      "@id": "sec:delegator",
      "@type": "@id"
    },
    "domain": "sec:domain",
    "expirationDate": {
      "@id": "sec:expiration",
      "@type": "xsd:dateTime"
    },
    "invocationTarget": {
      "@id": "sec:invocationTarget",
      "@type": "@id"
    },
    "invoker": {
      "@id": "sec:invoker",
      "@type": "@id"
    },
    "jws": "sec:jws",
    "keyAgreement": {
      "@id": "sec:keyAgreementMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "nonce": "sec:nonce",
    "owner": {
      "@id": "sec:owner",
      "@type": "@id"
    },
    "proof": {
      "@id": "sec:proof",
      "@type": "@id",
      "@container": "@graph"
    },
    "proofPurpose": {
      "@id": "sec:proofPurpose",
      "@type": "@vocab"
    },
    "proofValue": "sec:proofValue",
    "publicKey": {
      "@id": "sec:publicKey",
      "@type": "@id",
      "@container": "@set"
    },
    "publicKeyBase58": "sec:publicKeyBase58",
    "publicKeyPem": "sec:publicKeyPem",
    "publicKeyJwk": {
      "@id": "sec:publicKeyJwk",
      "@type": "@json"
    },
    "revoked": {
      "@id": "sec:revoked",
      "@type": "xsd:dateTime"
    },
    "service": {
      "@id": "didv:service",
      "@type": "@id",
      "@container": "@set"
    },
    "serviceEndpoint": {
      "@id": "didv:serviceEndpoint",
      "@type": "@id"
    },
    "updated": {
      "@id": "dc:modified",
      "@type": "xsd:dateTime"
    },
    "verificationMethod": {
      "@id": "sec:verificationMethod",
      "@type": "@id"
    }
  }
}
`

const didV011Context = `
{
  "@context": {
    "@version": 1.1,
    "id": "@id",
    "type": "@type",
    "dc": "http://purl.org/dc/terms/",
    "schema": "http://schema.org/",
    "sec": "https://w3id.org/security#",
    "didv": "https://w3id.org/did#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "EcdsaSecp256k1Signature2019": "sec:EcdsaSecp256k1Signature2019",
    "EcdsaSecp256k1VerificationKey2019": "sec:EcdsaSecp256k1VerificationKey2019",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "Ed25519VerificationKey2018": "sec:Ed25519VerificationKey2018",
    "RsaSignature2018": "sec:RsaSignature2018",
    "RsaVerificationKey2018": "sec:RsaVerificationKey2018",
    "X25519KeyAgreementKey2019": "sec:X25519KeyAgreementKey2019",
    "SchnorrSecp256k1Signature2019": "sec:SchnorrSecp256k1Signature2019",
    "SchnorrSecp256k1VerificationKey2019": "sec:SchnorrSecp256k1VerificationKey2019",
    "ServiceEndpointProxyService": "didv:ServiceEndpointProxyService",
    "allowedAction": "sec:allowedAction",
    "assertionMethod": {
      "@id": "sec:assertionMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "authentication": {
      "@id": "sec:authenticationMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "capability": {
      "@id": "sec:capability",
      "@type": "@id"
    },
    "capabilityAction": "sec:capabilityAction",
    "capabilityChain": {
      "@id": "sec:capabilityChain",
      "@type": "@id",
      "@container": "@list"
    },
    "capabilityDelegation": {
      "@id": "sec:capabilityDelegationMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "capabilityInvocation": {
      "@id": "sec:capabilityInvocationMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "capabilityStatusList": {
      "@id": "sec:capabilityStatusList",
      "@type": "@id"
    },
    "canonicalizationAlgorithm": "sec:canonicalizationAlgorithm",
    "caveat": {
      "@id": "sec:caveat",
      "@type": "@id",
      "@container": "@set"
    },
    "challenge": "sec:challenge",
    "controller": {
      "@id": "sec:controller",
      "@type": "@id"
    },
    "created": {
      "@id": "dc:created",
      "@type": "xsd:dateTime"
    },
    "creator": {
      "@id": "dc:creator",
      "@type": "@id"
    },
    "delegator": {
      "@id": "sec:delegator",
      "@type": "@id"
    },
    "domain": "sec:domain",
    "expirationDate": {
      "@id": "sec:expiration",
      "@type": "xsd:dateTime"
    },
    "invocationTarget": {
      "@id": "sec:invocationTarget",
      "@type": "@id"
    },
    "invoker": {
      "@id": "sec:invoker",
      "@type": "@id"
    },
    "jws": "sec:jws",
    "keyAgreement": {
      "@id": "sec:keyAgreementMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "nonce": "sec:nonce",
    "owner": {
      "@id": "sec:owner",
      "@type": "@id"
    },
    "proof": {
      "@id": "sec:proof",
      "@type": "@id",
      "@container": "@graph"
    },
    "proofPurpose": {
      "@id": "sec:proofPurpose",
      "@type": "@vocab"
    },
    "proofValue": "sec:proofValue",
    "publicKey": {
      "@id": "sec:publicKey",
      "@type": "@id",
      "@container": "@set"
    },
    "publicKeyBase58": "sec:publicKeyBase58",
    "publicKeyPem": "sec:publicKeyPem",
    "revoked": {
      "@id": "sec:revoked",
      "@type": "xsd:dateTime"
    },
    "service": {
      "@id": "didv:service",
      "@type": "@id",
      "@container": "@set"
    },
    "serviceEndpoint": {
      "@id": "didv:serviceEndpoint",
      "@type": "@id"
    },
    "verificationMethod": {
      "@id": "sec:verificationMethod",
      "@type": "@id"
    }
  }
}`

const securityV1Context = `
{
  "@context": {
    "id": "@id",
    "type": "@type",

    "dc": "http://purl.org/dc/terms/",
    "sec": "https://w3id.org/security#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",

    "EcdsaKoblitzSignature2016": "sec:EcdsaKoblitzSignature2016",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "EncryptedMessage": "sec:EncryptedMessage",
    "GraphSignature2012": "sec:GraphSignature2012",
    "LinkedDataSignature2015": "sec:LinkedDataSignature2015",
    "LinkedDataSignature2016": "sec:LinkedDataSignature2016",
    "CryptographicKey": "sec:Key",

    "authenticationTag": "sec:authenticationTag",
    "canonicalizationAlgorithm": "sec:canonicalizationAlgorithm",
    "cipherAlgorithm": "sec:cipherAlgorithm",
    "cipherData": "sec:cipherData",
    "cipherKey": "sec:cipherKey",
    "created": {"@id": "dc:created", "@type": "xsd:dateTime"},
    "creator": {"@id": "dc:creator", "@type": "@id"},
    "digestAlgorithm": "sec:digestAlgorithm",
    "digestValue": "sec:digestValue",
    "domain": "sec:domain",
    "encryptionKey": "sec:encryptionKey",
    "expiration": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
    "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
    "initializationVector": "sec:initializationVector",
    "iterationCount": "sec:iterationCount",
    "nonce": "sec:nonce",
    "normalizationAlgorithm": "sec:normalizationAlgorithm",
    "owner": {"@id": "sec:owner", "@type": "@id"},
    "password": "sec:password",
    "privateKey": {"@id": "sec:privateKey", "@type": "@id"},
    "privateKeyPem": "sec:privateKeyPem",
    "publicKey": {"@id": "sec:publicKey", "@type": "@id"},
    "publicKeyBase58": "sec:publicKeyBase58",
    "publicKeyPem": "sec:publicKeyPem",
    "publicKeyWif": "sec:publicKeyWif",
    "publicKeyService": {"@id": "sec:publicKeyService", "@type": "@id"},
    "revoked": {"@id": "sec:revoked", "@type": "xsd:dateTime"},
    "salt": "sec:salt",
    "signature": "sec:signature",
    "signatureAlgorithm": "sec:signingAlgorithm",
    "signatureValue": "sec:signatureValue"
  }
}
`

const securityV2Context = `
{
  "@context": [{
    "@version": 1.1
  }, "https://w3id.org/security/v1", {
    "AesKeyWrappingKey2019": "sec:AesKeyWrappingKey2019",
    "DeleteKeyOperation": "sec:DeleteKeyOperation",
    "DeriveSecretOperation": "sec:DeriveSecretOperation",
    "EcdsaSecp256k1Signature2019": "sec:EcdsaSecp256k1Signature2019",
    "EcdsaSecp256r1Signature2019": "sec:EcdsaSecp256r1Signature2019",
    "EcdsaSecp256k1VerificationKey2019": "sec:EcdsaSecp256k1VerificationKey2019",
    "EcdsaSecp256r1VerificationKey2019": "sec:EcdsaSecp256r1VerificationKey2019",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "Ed25519VerificationKey2018": "sec:Ed25519VerificationKey2018",
    "EquihashProof2018": "sec:EquihashProof2018",
    "ExportKeyOperation": "sec:ExportKeyOperation",
    "GenerateKeyOperation": "sec:GenerateKeyOperation",
    "KmsOperation": "sec:KmsOperation",
    "RevokeKeyOperation": "sec:RevokeKeyOperation",
    "RsaSignature2018": "sec:RsaSignature2018",
    "RsaVerificationKey2018": "sec:RsaVerificationKey2018",
    "Sha256HmacKey2019": "sec:Sha256HmacKey2019",
    "SignOperation": "sec:SignOperation",
    "UnwrapKeyOperation": "sec:UnwrapKeyOperation",
    "VerifyOperation": "sec:VerifyOperation",
    "WrapKeyOperation": "sec:WrapKeyOperation",
    "X25519KeyAgreementKey2019": "sec:X25519KeyAgreementKey2019",

    "allowedAction": "sec:allowedAction",
    "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
    "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"},
    "capability": {"@id": "sec:capability", "@type": "@id"},
    "capabilityAction": "sec:capabilityAction",
    "capabilityChain": {"@id": "sec:capabilityChain", "@type": "@id", "@container": "@list"},
    "capabilityDelegation": {"@id": "sec:capabilityDelegationMethod", "@type": "@id", "@container": "@set"},
    "capabilityInvocation": {"@id": "sec:capabilityInvocationMethod", "@type": "@id", "@container": "@set"},
    "caveat": {"@id": "sec:caveat", "@type": "@id", "@container": "@set"},
    "challenge": "sec:challenge",
    "ciphertext": "sec:ciphertext",
    "controller": {"@id": "sec:controller", "@type": "@id"},
    "delegator": {"@id": "sec:delegator", "@type": "@id"},
    "equihashParameterK": {"@id": "sec:equihashParameterK", "@type": "xsd:integer"},
    "equihashParameterN": {"@id": "sec:equihashParameterN", "@type": "xsd:integer"},
    "invocationTarget": {"@id": "sec:invocationTarget", "@type": "@id"},
    "invoker": {"@id": "sec:invoker", "@type": "@id"},
    "jws": "sec:jws",
    "keyAgreement": {"@id": "sec:keyAgreementMethod", "@type": "@id", "@container": "@set"},
    "kmsModule": {"@id": "sec:kmsModule"},
    "parentCapability": {"@id": "sec:parentCapability", "@type": "@id"},
    "plaintext": "sec:plaintext",
    "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
    "proofPurpose": {"@id": "sec:proofPurpose", "@type": "@vocab"},
    "proofValue": "sec:proofValue",
    "referenceId": "sec:referenceId",
    "unwrappedKey": "sec:unwrappedKey",
    "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"},
    "verifyData": "sec:verifyData",
    "wrappedKey": "sec:wrappedKey"
  }]
}
`
