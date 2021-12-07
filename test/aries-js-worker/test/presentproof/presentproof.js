/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {environment} from "../environment.js";
import {newDIDExchangeClient, newDIDExchangeRESTClient,} from "../didexchange/didexchange_e2e.js";
import {watchForEvent} from "../common.js";
import "/base/node_modules/base64-js/base64js.min.js";
import "/base/node_modules/base-58/Base58.js";

const agent1ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.SECOND_USER_HOST}:${environment.SECOND_USER_API_PORT}`;
const agent2ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`;
const restMode = "rest";
const wasmMode = "wasm";
const actionsTopic = "present-proof_actions";
const statesTopic = "present-proof_states";
const stateDone = "done";
const verifierID = "verifier";
const proverID = "prover";

const presentation = {
    lastmod_time: "0001-01-01T00:00:00Z",
    data: {
        base64: "ZXlKaGJHY2lPaUp1YjI1bElpd2lkSGx3SWpvaVNsZFVJbjAuZXlKcGMzTWlPaUprYVdRNlpYaGhiWEJzWlRwbFltWmxZakZtTnpFeVpXSmpObVl4WXpJM05tVXhNbVZqTWpFaUxDSnFkR2tpT2lKMWNtNDZkWFZwWkRvek9UYzRNelEwWmkwNE5UazJMVFJqTTJFdFlUazNPQzA0Wm1OaFltRXpPVEF6WXpVaUxDSjJjQ0k2ZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3ZNakF4T0M5amNtVmtaVzUwYVdGc2N5OTJNU0lzSW1oMGRIQnpPaTh2ZDNkM0xuY3pMbTl5Wnk4eU1ERTRMMk55WldSbGJuUnBZV3h6TDJWNFlXMXdiR1Z6TDNZeElsMHNJbWh2YkdSbGNpSTZJbVJwWkRwbGVHRnRjR3hsT21WaVptVmlNV1kzTVRKbFltTTJaakZqTWpjMlpURXlaV015TVNJc0ltbGtJam9pZFhKdU9uVjFhV1E2TXprM09ETTBOR1l0T0RVNU5pMDBZek5oTFdFNU56Z3RPR1pqWVdKaE16a3dNMk0xSWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFVISmxjMlZ1ZEdGMGFXOXVJaXdpUTNKbFpHVnVkR2xoYkUxaGJtRm5aWEpRY21WelpXNTBZWFJwYjI0aVhTd2lkbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpT201MWJHeDlmUS4=",
    },
};

const presentationDefinition = {
    presentation_definition: {
        id: "7dd10550-adb2-4d28-819f-f601680c1fcd",
        input_descriptors: [
            {
                id:
                    "adcc44d9-1c0e-4e8f-9f21-6eda7dba9160",
                schema: [
                    {
                        uri: "https://example.org/examples#UniversityDegreeCredential"
                    },
                ],
                constraints: {
                    limit_disclosure: "required",
                    fields: [
                        {
                            path: [
                                "$.credentialSubject.degree.degreeSchool",
                            ],
                            filter: {
                                type: "string",
                            },
                        },
                    ],
                },
            },
        ],
    },
};

const credential = {
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1",
        "https://w3id.org/security/bbs/v1",
    ],
    credentialSubject: {
        degree: {
            degree: "MIT",
            degreeSchool: "MIT school",
            type: "BachelorDegree",
        },
        id: "did:example:b34ca6cd37bbf23",
        name: "Jayden Doe",
        spouse: "did:example:c276e12ec21ebfeb1f712ebc6f1",
    },
    description: "Government of Example Permanent Resident Card.",
    expirationDate: "2022-03-10T13:16:45.261647327+02:00",
    id: "https://issuer.oidp.uscis.gov/credentials/83627465",
    identifier: "83627465",
    issuanceDate: "2021-03-10T13:16:45.261647217+02:00",
    issuer: "did:example:489398593",
    name: "Permanent Resident Card",
    type: ["VerifiableCredential", "UniversityDegreeCredential"],
};

const v2 = "v2";
const v3 = "v3";

describe("Present Proof (v2) - The Verifier begins with a request presentation", async function () {
    describe(restMode, function () {
        presentProof(restMode, v2);
    });
    describe(wasmMode, function () {
        presentProof(wasmMode, v2);
    });
});

describe("Present Proof (v3) - The Verifier begins with a request presentation", async function () {
    describe(restMode, function () {
        presentProof(restMode, v3);
    });
    describe(wasmMode, function () {
        presentProof(wasmMode, v3);
    });
});

describe("Present Proof (v2) - The Verifier begins with a request presentation (BBS+)", async function () {
    describe(restMode, function () {
        presentProofBBS(restMode, v2);
    });
    describe(wasmMode, function () {
        presentProofBBS(wasmMode, v2);
    });
});

describe("Present Proof (v3) - The Verifier begins with a request presentation (BBS+)", async function () {
    describe(restMode, function () {
        presentProofBBS(restMode, v3);
    });
    describe(wasmMode, function () {
        presentProofBBS(wasmMode, v3);
    });
});

async function presentProofBBS(mode, ver) {
    let connections;
    let didClient;
    let verifier, prover;

    before(async () => {
        if (mode === restMode) {
            didClient = await newDIDExchangeRESTClient(
                agent2ControllerApiUrl,
                agent1ControllerApiUrl
            );
        } else {
            didClient = await newDIDExchangeClient(verifierID + ver, proverID + ver);
        }

        assert.isNotNull(didClient);

        if (ver === v3) {
            connections = await didClient.createDIDCommV2Connection();
            assert.isNotEmpty(connections);

        } else {
            connections = await didClient.performDIDExchangeE2E();
            assert.isNotEmpty(connections);
        }

        verifier = didClient.agent1;
        prover = didClient.agent2;
    });

    after(async () => {
        await didClient.destroy();
    });

    let proverAction;
    let verifierConn;

    it("Verifier sends a request presentation to the Prover", async function () {
        proverAction = getAction(prover);
        verifierConn = await connection(verifier, connections[0]);
        let ID = "6dd10550-adb3-1d28-519f-f601680c2fcd";

        if (ver === v3) {
            return verifier.presentproof.sendRequestPresentationV3({
                my_did: verifierConn.MyDID,
                their_did: verifierConn.TheirDID,
                request_presentation: {
                    body: {will_confirm: true},
                    attachments: [
                        {
                            id: ID,
                            format: "dif/presentation-exchange/definitions@v1.0",
                            lastmod_time: "0001-01-01T00:00:00Z",
                            data: {
                                json: presentationDefinition,
                            },
                        },
                    ],
                },
            });
        }

        return verifier.presentproof.sendRequestPresentation({
            my_did: verifierConn.MyDID,
            their_did: verifierConn.TheirDID,
            request_presentation: {
                will_confirm: true,
                formats: [
                    {
                        attach_id: ID,
                        format: "dif/presentation-exchange/definitions@v1.0",
                    },
                ],
                "request_presentations~attach": [
                    {
                        "@id": ID,
                        lastmod_time: "0001-01-01T00:00:00Z",
                        data: {
                            json: presentationDefinition,
                        },
                    },
                ],
            },
        });
    });

    let verifierAction;
    it("Prover accepts a request and sends a presentation to the Verifier", async function () {
        verifierAction = getAction(verifier);
        let kmsKey = await prover.kms.createKeySet({keyType: "BLS12381G2"});

        let {didKey, keyID} = CreateBBSDIDKey(kmsKey.publicKey);

        let resp = await prover.verifiable.signCredential({
            credential: credential,
            did: didKey,
            kid: kmsKey.keyID,
            verificationMethod: keyID,
            SignatureRepresentation: 0,
            SignatureType: "BbsBlsSignature2020",
        });

        let vp = JSON.stringify(resp.verifiableCredential);

        let verifiableCredential = [];
        for (let i = 0; i < vp.length; i++) {
            verifiableCredential.push(vp.charCodeAt(i));
        }

        if (ver === v3) {
            return prover.presentproof.acceptRequestPresentationV3({
                piid: (await proverAction).Properties.piid,
                presentation: {
                    attachments: [
                        {
                            media_type: "application/ld+json",
                            data: {
                                base64: base64js.fromByteArray(
                                    verifiableCredential
                                ),
                            },
                        },
                    ],
                },
            });
        }

        return prover.presentproof.acceptRequestPresentation({
            piid: (await proverAction).Properties.piid,
            presentation: {
                "presentations~attach": [
                    {
                        "mime-type": "application/ld+json",
                        data: {
                            base64: base64js.fromByteArray(
                                verifiableCredential
                            ),
                        },
                    },
                ],
            },
        });
    });

    const name = mode + ver + ".js.presentation.bbs.test";

    let presentationRes;
    it("Verifier accepts a presentation", async function () {
        presentationRes = getPresentation(verifier, name);

        return verifier.presentproof.acceptPresentation({
            piid: (await verifierAction).Properties.piid,
            names: [name],
        });
    });

    it("Verifier checks presentation", async function () {
        let presentation = await presentationRes;

        assert.equal(presentation.my_did, verifierConn.MyDID);
        assert.equal(presentation.their_did, verifierConn.TheirDID);
    });
}

// scenarios
async function presentProof(mode, ver) {
    let connections;
    let didClient;
    let verifier, prover;

    before(async () => {
        if (mode === restMode) {
            didClient = await newDIDExchangeRESTClient(
                agent2ControllerApiUrl,
                agent1ControllerApiUrl
            );
        } else {
            didClient = await newDIDExchangeClient(verifierID + ver, proverID + ver);
        }

        assert.isNotNull(didClient);

        if (ver === v3) {
            connections = await didClient.createDIDCommV2Connection();
            assert.isNotEmpty(connections);

        } else {
            connections = await didClient.performDIDExchangeE2E();
            assert.isNotEmpty(connections);
        }

        verifier = didClient.agent1;
        prover = didClient.agent2;
    });

    after(async () => {
        await didClient.destroy();
    });

    let proverAction;
    let verifierConn;

    it("Verifier sends a request presentation to the Prover", async function () {
        proverAction = getAction(prover);
        verifierConn = await connection(verifier, connections[0]);

        if (ver === v3) {
            return verifier.presentproof.sendRequestPresentationV3({
                my_did: verifierConn.MyDID,
                their_did: verifierConn.TheirDID,
                request_presentation: {body: {will_confirm: true}},
            });
        }

        return verifier.presentproof.sendRequestPresentation({
            my_did: verifierConn.MyDID,
            their_did: verifierConn.TheirDID,
            request_presentation: {will_confirm: true},
        });
    });

    let verifierAction;
    it("Prover accepts a request and sends a presentation to the Verifier", async function () {
        verifierAction = getAction(verifier);

        if (ver === v3) {
            return prover.presentproof.acceptRequestPresentationV3({
                piid: (await proverAction).Properties.piid,
                presentation: {attachments: [presentation]}
            });
        }

        return prover.presentproof.acceptRequestPresentation({
            piid: (await proverAction).Properties.piid,
            presentation: {
                "presentations~attach": [presentation]
            },
        });
    });

    const name = mode + ver + ".js.presentation.test";

    let presentationRes;
    it("Verifier accepts a presentation", async function () {
        presentationRes = getPresentation(verifier, name);

        return verifier.presentproof.acceptPresentation({
            piid: (await verifierAction).Properties.piid,
            names: [name],
        });
    });

    it("Verifier checks presentation", async function () {
        let presentation = await presentationRes;

        assert.equal(presentation.my_did, verifierConn.MyDID);
        assert.equal(presentation.their_did, verifierConn.TheirDID);
    });
}

async function getPresentation(agent, name) {
    await watchForEvent(agent, {
        topic: statesTopic,
        stateID: stateDone,
    });

    let res = await agent.verifiable.getPresentations();
    if (res.result) {
        for (let j = 0; j < res.result.length; j++) {
            if (res.result[j].name === name) {
                return res.result[j];
            }
        }
    }

    throw new Error("presentation not found");
}

async function getAction(agent) {
    return watchForEvent(agent, {
        topic: actionsTopic,
    });
}

async function connection(agent, conn) {
    let res = await agent.didexchange.queryConnectionByID({
        id: conn,
    });

    return res.result;
}

function CreateBBSDIDKey(pubKeyEnc) {
    let methodID = Base58.encode(
        new Uint8Array([
            ...new Uint8Array([235, 1]),
            ...base64js.toByteArray(pubKeyEnc),
        ])
    );
    methodID = "z" + methodID;

    let didKey = "did:key:" + methodID;
    let keyID = didKey + "#" + methodID;

    return {
        didKey: didKey,
        keyID: keyID,
    };
}
