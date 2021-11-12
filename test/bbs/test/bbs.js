/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const fs = require("fs");
const assert = require('chai').assert;

const {signAries, verifyAries, deriveProofAries, verifyProofAries} = require("../src/vc.js");

const {Bls12381G2KeyPair, BbsBlsSignature2020, BbsBlsSignatureProof2020, deriveProof: deriveProofMattr} = require("@mattrglobal/jsonld-signatures-bbs");
const {extendContextLoader, sign: signMattr, verify: verifyMattr, purposes,} = require("jsonld-signatures");
const {documentLoaders} = require("jsonld");

const bbsContext = JSON.parse(fs.readFileSync("data/context/ldp-bbs2020.jsonld", 'utf-8'));
const citizenVocab = JSON.parse(fs.readFileSync("data/context/citizenship.jsonld", 'utf-8'));
const vcexampleVocab = JSON.parse(fs.readFileSync("data/context/vcexample.jsonld", 'utf-8'));
const keyPairOptions = JSON.parse(fs.readFileSync("data/keyPair.json", 'utf-8'));
const keyPair2Options = JSON.parse(fs.readFileSync("data/keyPair2.json", 'utf-8'));
const revealDocument = JSON.parse(fs.readFileSync("data/revealDocument.json", 'utf-8'));
const case19RevealDocument = JSON.parse(fs.readFileSync("data/case-19-reveal.json", 'utf-8'));

const documents = {
    "did:example:489398593#test": keyPairOptions,
    "did:example:489398593": {
        "@context": "https://w3id.org/security/v2",
        "id": "did:example:489398593",
        "assertionMethod": ["did:example:489398593#test"]
    },
    "did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2#zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2": keyPair2Options,
    "did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2": {
        "@context": "https://w3id.org/security/v2",
        "id": "did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2",
        "assertionMethod": ["did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2#zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2"]
    },
    "https://w3id.org/security/bbs/v1": bbsContext,
    "https://w3id.org/citizenship/v1": citizenVocab,
    "https://www.w3.org/2018/credentials/examples/v1": vcexampleVocab
};

const customDocLoader = (url) => {
    const context = documents[url];

    if (context) {
        return {
            contextUrl: null, // this is for a context via a link header
            document: context, // this is the actual document that was loaded
            documentUrl: url // this is the actual context URL after redirects
        };
    }

    return documentLoaders.node()(url)
};

const documentLoader = extendContextLoader(customDocLoader);

describe("BBS+ interop fixtures", function () {
    this.timeout(10_000);

    before(async function () {
        require("../src/wasm_exec.js");

        const go = new Go();

        const obj = await WebAssembly.instantiate(fs.readFileSync('src/bbs.wasm'), go.importObject);
        go.run(obj.instance);

        await sleep(500); // give wasm some time to initialize
    })

    it('sign with Aries and verify with Mattr', async function () {
        const vc = JSON.parse(fs.readFileSync("data/inputDocument.json", 'utf-8'));

        let signedVC = await signAries(keyPairOptions.privateKeyBase58, JSON.stringify(vc), "did:example:489398593#test");

        let verified = await verifyMattr(JSON.parse(signedVC), {
            suite: new BbsBlsSignature2020(),
            purpose: new purposes.AssertionProofPurpose(),
            documentLoader
        });

        assert.isTrue(verified.verified);
    })

    it('sign with Mattr and verify with Aries', async function () {
        const vc = JSON.parse(fs.readFileSync("data/inputDocument.json", 'utf-8'));
        const keyPair = await new Bls12381G2KeyPair(keyPairOptions);

        const signedDocument = await signMattr(vc, {
            suite: new BbsBlsSignature2020({key: keyPair}),
            purpose: new purposes.AssertionProofPurpose(),
            documentLoader
        });

        await verifyAries(keyPairOptions.publicKeyBase58, JSON.stringify(signedDocument));
    })

    it('derive signature proof with Aries and verify with Mattr', async function () {
        const vc = JSON.parse(fs.readFileSync("data/inputDocument.json", 'utf-8'));

        let signedVC = await signAries(keyPairOptions.privateKeyBase58, JSON.stringify(vc), "did:example:489398593#test");

        const nonce = "lEixQKDQvRecCifKl789TQj+Ii6YWDLSwn3AxR0VpPJ1QV5htod/0VCchVf1zVM0y2E=";
        let derivedProof = await deriveProofAries(keyPairOptions.publicKeyBase58, signedVC, JSON.stringify(revealDocument), nonce);

        let verified = await verifyMattr(JSON.parse(derivedProof), {
            suite: new BbsBlsSignatureProof2020(),
            purpose: new purposes.AssertionProofPurpose(),
            documentLoader
        });
        assert.isTrue(verified.verified);
    })

    it('derive signature proof with Mattr and verify with Aries', async function () {
        const vc = JSON.parse(fs.readFileSync("data/inputDocument.json", 'utf-8'));
        const keyPair = await new Bls12381G2KeyPair(keyPairOptions);

        const signedDocument = await signMattr(vc, {
            suite: new BbsBlsSignature2020({key: keyPair}),
            purpose: new purposes.AssertionProofPurpose(),
            documentLoader
        });

        const derivedProof = await deriveProofMattr(signedDocument, revealDocument, {
            suite: new BbsBlsSignatureProof2020(),
            documentLoader,
        });

        await verifyProofAries(keyPairOptions.publicKeyBase58, JSON.stringify(derivedProof));
    })

    it('case 18->19: derive signature proof with Aries and verify with Mattr', async function () {
        const vc = JSON.parse(fs.readFileSync("data/case-18.json", 'utf-8'));

        const nonce = "lEixQKDQvRecCifKl789TQj+Ii6YWDLSwn3AxR0VpPJ1QV5htod/0VCchVf1zVM0y2E=";

        let derivedProof = await deriveProofAries(keyPair2Options.publicKeyBase58, JSON.stringify(vc), JSON.stringify(case19RevealDocument), nonce);

        let verified = await verifyMattr(JSON.parse(derivedProof), {
            suite: new BbsBlsSignatureProof2020(),
            purpose: new purposes.AssertionProofPurpose(),
            documentLoader
        });
        assert.isTrue(verified.verified);
    })

    it('case 18->19: derive signature proof with Mattr and verify with Aries', async function () {
        const vc = JSON.parse(fs.readFileSync("data/case-18.json", 'utf-8'));
        const keyPair = await new Bls12381G2KeyPair(keyPairOptions);

        const nonce = "lEixQKDQvRecCifKl789TQj+Ii6YWDLSwn3AxR0VpPJ1QV5htod/0VCchVf1zVM0y2E=";
        let nonceBuffer = Buffer.from(nonce, "base64")

        const derivedProof = await deriveProofMattr(vc, case19RevealDocument, {
            suite: new BbsBlsSignatureProof2020(),
            nonce: new Uint8Array(nonceBuffer),
            documentLoader
        });

        await verifyProofAries(keyPair2Options.publicKeyBase58, JSON.stringify(derivedProof));
    })
})

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
