/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const fs = require("fs");
const assert = require('chai').assert;

const {signAries, verifyAries} = require("../src/vc.js");

const {Bls12381G2KeyPair, BbsBlsSignature2020} = require("@mattrglobal/jsonld-signatures-bbs");
const {extendContextLoader, sign: signMattr, verify: verifyMattr, purposes} = require("jsonld-signatures");
const {documentLoaders} = require("jsonld");

const bbsContext = JSON.parse(fs.readFileSync("data/context/ldp-bbs2020.jsonld", 'utf-8'));
const citizenVocab = JSON.parse(fs.readFileSync("data/context/citizenship.jsonld", 'utf-8'));
const vc = JSON.parse(fs.readFileSync("data/inputDocument.json", 'utf-8'));
const keyPairOptions = JSON.parse(fs.readFileSync("data/keyPair.json", 'utf-8'));

const documents = {
    "did:example:489398593#test": keyPairOptions,
    "did:example:489398593": {
        "@context": "https://w3id.org/security/v2",
        "id": "did:example:489398593",
        "assertionMethod": ["did:example:489398593#test"]
    },
    "https://w3c-ccg.github.io/ldp-bbs2020/context/v1": bbsContext,
    "https://w3id.org/citizenship/v1": citizenVocab
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
        let signedVC = await signAries(keyPairOptions.privateKeyBase58, JSON.stringify(vc), "did:example:489398593#test");

        let verified = await verifyMattr(JSON.parse(signedVC), {
            suite: new BbsBlsSignature2020(),
            purpose: new purposes.AssertionProofPurpose(),
            documentLoader
        });

        assert.isTrue(verified.verified);
    })

    it('sign with Mattr and verify with Aries', async function () {
        const keyPair = await new Bls12381G2KeyPair(keyPairOptions);

        const signedDocument = await signMattr(vc, {
            suite: new BbsBlsSignature2020({key: keyPair}),
            purpose: new purposes.AssertionProofPurpose(),
            documentLoader
        });

        await verifyAries(keyPairOptions.publicKeyBase58, JSON.stringify(signedDocument));
    })
})

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
