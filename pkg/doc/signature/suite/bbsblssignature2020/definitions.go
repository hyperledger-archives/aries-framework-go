package bbsblssignature2020

const ldpBBS2020JSONLD = `
{
  "@context": {
    "@version": 1.1,
    "id": "@id",
    "type": "@type",
    "ldssk": "https://w3c-ccg.github.io/ldp-bbs2020/context/v1#",
    "BbsBlsSignature2020": {
      "@id": "https://w3c-ccg.github.io/ldp-bbs2020/context/v1#BbsBlsSignature2020",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "challenge": "sec:challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "xsd:dateTime"
        },
        "domain": "sec:domain",
        "proofValue": "sec:proofValue",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "sec": "https://w3id.org/security#",
            "assertionMethod": {
              "@id": "sec:assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "sec:authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "verificationMethod": {
          "@id": "sec:verificationMethod",
          "@type": "@id"
        }
      }
    },
    "BbsBlsSignatureProof2020": {
      "@id": "https://w3c-ccg.github.io/ldp-bbs2020/context/v1#BbsBlsSignatureProof2020",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "challenge": "sec:challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "xsd:dateTime"
        },
        "domain": "sec:domain",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "sec": "https://w3id.org/security#",
            "assertionMethod": {
              "@id": "sec:assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "sec:authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {
          "@id": "sec:verificationMethod",
          "@type": "@id"
        }
      }
    },
    "Bls12381G2Key2020": "ldssk:Bls12381G2Key2020"
  }
}
`

const securityJSONLD = `
{
  "@context": [{
    "@version": 1.1
  }, "https://w3id.org/security/v1", {
    "AesKeyWrappingKey2019": "sec:AesKeyWrappingKey2019",
    "DeleteKeyOperation": "sec:DeleteKeyOperation",
    "DeriveSecretOperation": "sec:DeriveSecretOperation",
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
