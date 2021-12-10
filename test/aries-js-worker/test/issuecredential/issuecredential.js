/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {environment} from "../environment.js";
import {newDIDExchangeClient, newDIDExchangeRESTClient} from "../didexchange/didexchange_e2e.js";
import {watchForEvent} from "../common.js";

const agent1ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.SECOND_USER_HOST}:${environment.SECOND_USER_API_PORT}`
const agent2ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`

const restMode = 'rest'
const wasmMode = 'wasm'
const actionsTopic = "issue-credential_actions"
const statesTopic = "issue-credential_states"
const stateDone = "done"

const issueCredentialPayloadV2 = {
    "credentials~attach": [{
        "lastmod_time": "0001-01-01T00:00:00Z",
        "data": {
            "json": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "credentialSubject": {
                    "ID": "SubjectID"
                },
                "id": "http://example.edu/credentials/1872",
                "issuanceDate": "2010-01-01T19:23:24Z",
                "issuer": {
                    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
                    "name": "Example University"
                },
                "referenceNumber": 83294847,
                "type": [
                    "VerifiableCredential",
                    "UniversityDegreeCredential"
                ]
            }
        }
    }]
}

const issueCredentialPayloadV3 = {
    "attachments": [{
        "lastmod_time": "0001-01-01T00:00:00Z",
        "data": {
            "json": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "credentialSubject": {
                    "ID": "SubjectID"
                },
                "id": "http://example.edu/credentials/1872",
                "issuanceDate": "2010-01-01T19:23:24Z",
                "issuer": {
                    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
                    "name": "Example University"
                },
                "referenceNumber": 83294847,
                "type": [
                    "VerifiableCredential",
                    "UniversityDegreeCredential"
                ]
            }
        }
    }]
}
const v2 = "v2";
const v3 = "v3";

describe("Issue credential (v2) - The Holder begins with a request", async function() {
    describe(restMode, function() { issueCredential(restMode,v2) })
    describe(wasmMode, function() { issueCredential(wasmMode,v2) })
})

describe("Issue credential (v3) - The Holder begins with a request", async function() {
    describe(restMode, function() { issueCredential(restMode,v3) })
    describe(wasmMode, function() { issueCredential(wasmMode,v3) })
})

// scenarios
async function issueCredential (mode,ver) {
    const holderID = "holder"
    const issuerID = "issuer"
    let connections
    let didexClient
    let holder, issuer

    before(async () => {
        if (mode === restMode){
            didexClient = await newDIDExchangeRESTClient(agent2ControllerApiUrl,agent1ControllerApiUrl)
        }else {
            didexClient = await newDIDExchangeClient(holderID+ver,issuerID+ver)
        }

        assert.isNotNull(didexClient)

        if (ver === v3) {
            connections = await didexClient.createDIDCommV2Connection();
            assert.isNotEmpty(connections);
        } else {
            connections = await didexClient.performDIDExchangeE2E()
            assert.isNotEmpty(connections)
        }

        holder = didexClient.agent1
        issuer = didexClient.agent2
    })

    after(async () => {
        await didexClient.destroy()
    })

    let issuerAction;
    let holderConn;

    it("Holder requests credential from the Issuer", async function () {
        holderConn = await connection(holder, connections[0])
        issuerAction = getAction(issuer)
        if (ver === v3) {
            return holder.issuecredential.sendRequestV3({
                my_did: holderConn.MyDID,
                their_did: holderConn.TheirDID,
                request_credential: {},
            })
        }

            return holder.issuecredential.sendRequest({
            my_did: holderConn.MyDID,
            their_did: holderConn.TheirDID,
            request_credential: {},
        })
    })

    let holderAction;
    it("Issuer accepts request and sends credential to the Holder", async function () {
        holderAction = getAction(holder)
        if (ver === v3) {
            return issuer.issuecredential.acceptRequestV3({
                piid: (await issuerAction).Properties.piid,
                issue_credential: issueCredentialPayloadV3,
            })
        }
            return issuer.issuecredential.acceptRequest({
            piid: (await issuerAction).Properties.piid,
            issue_credential: issueCredentialPayloadV2,
        })
    })

    const credentialName = mode + ver + "license"

    let credential;
    it("Holder accepts credential", async function () {
        credential = getCredential(holder, credentialName)
        return holder.issuecredential.acceptCredential({
            piid: (await holderAction).Properties.piid,
            names: [credentialName],
        })
    })

    it("Checks credential", async function () {
        let cred = await credential;

        assert.equal(cred.my_did, holderConn.MyDID)
        assert.equal(cred.their_did, holderConn.TheirDID)
    })
}

async function getAction(agent) {
    return await watchForEvent(agent, {
        topic: actionsTopic,
    })
}

async function getCredential(agent, name) {
    await watchForEvent(agent, {
        topic: statesTopic,
        stateID: stateDone,
    })

    let res = await agent.verifiable.getCredentials();
    if (res.result) {
        for (let j = 0; j < res.result.length; j++) {
            if (res.result[j].name === name) {
                return res.result[j];
            }
        }
    }

    throw new Error("credential not found");
}

async function connection(agent, conn) {
    let res = await agent.didexchange.queryConnectionByID({
        id: conn
    })

    return res.result
}
