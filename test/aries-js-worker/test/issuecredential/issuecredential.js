/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
import {environment} from "../environment.js";
import {newDIDExchangeClient,newDIDExchangeRESTClient} from "../didexchange/didexchange_e2e.js";

const agent1ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.ROUTER_HOST}:${environment.ROUTER_API_PORT}`
const agent2ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`

const restMode = 'rest'
const wasmMode = 'wasm'

const issueCredentialPayload = {
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

describe("Issue credential - The Holder begins with a request", async function() {
    describe(restMode, function() { issueCredential(restMode) })
    describe(wasmMode, function() { issueCredential(wasmMode) })
})

// scenarios
async function issueCredential (mode) {
    const holderID = "holder"
    const issuerID = "issuer"
    let connections
    let didexClient
    let holder, issuer

    before(async () => {
        if (mode === restMode){
            didexClient = await newDIDExchangeRESTClient(agent2ControllerApiUrl,agent1ControllerApiUrl)
        }else {
            didexClient = await newDIDExchangeClient(holderID,issuerID)
        }

        assert.isNotNull(didexClient)

        connections = await didexClient.performDIDExchangeE2E()
        assert.isNotEmpty(connections)

        holder = didexClient.agent1
        issuer = didexClient.agent2
    })

    after(() => {
        didexClient.destroy()
    })

    it("Holder requests credential from the Issuer", async function() {
        let conn = await connection(holder, connections[0])
        return holder.issuecredential.sendRequest({
            my_did: conn.MyDID,
            their_did: conn.TheirDID,
            request_credential: {},
        })
    })

    it("Issuer accepts request and sends credential to the Holder", async function() {
        let action = await getAction(issuer)
        return issuer.issuecredential.acceptRequest({
            piid: action.piid,
            issue_credential: issueCredentialPayload,
            body: issueCredentialPayload
        })
    })

    const credentialName = "license"

    it("Holder accepts credential", async function() {
        let action = await getAction(holder)
        return holder.issuecredential.acceptCredential({
            piid: action.piid,
            names: [credentialName],
            body: [credentialName],
        })
    })

    it("Checks credential", async function() {
        return getCredential(holder, credentialName)
    })
}

const retries = 15;

async function getAction(agent) {
    for (let i = 0; i < retries; i++) {
        let resp = await agent.issuecredential.actions()
        if (resp.actions.length > 0) {
            return resp.actions[0]
        }

        await sleep(1000);
    }

    throw new Error("no action")
}

async function getCredential(agent, name) {
    for (let i = 0; i < retries; i++) {
        try {
            return await agent.verifiable.getCredentialByName({
                name: name
            })
        } catch (e) {}

        await sleep(1000);
    }

    throw new Error("no action")
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function connection(agent, conn) {
    let res = await agent.didexchange.queryConnectionByID({
        id: conn
    })

    return res.result
}