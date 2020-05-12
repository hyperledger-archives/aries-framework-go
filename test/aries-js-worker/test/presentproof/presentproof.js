/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
import {environment} from "../environment.js";
import {newDIDExchangeClient,newDIDExchangeRESTClient} from "../didexchange/didexchange_e2e.js";

const agent1ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.PUBLIC_ROUTER_HOST}:${environment.PUBLIC_ROUTER_API_PORT}`
const agent2ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`

const restMode = 'rest'
const wasmMode = 'wasm'

describe("Present Proof - The Verifier begins with a request presentation", async function() {
    describe(restMode, function() { presentProof(restMode) })
    describe(wasmMode, function() { presentProof(wasmMode) })
})

// scenarios
async function presentProof (mode) {
    const verifierID = "verifier"
    const proverID = "prover"
    let connections
    let didClient
    let verifier, prover

    before(async () => {
        if (mode === restMode){
            didClient = await newDIDExchangeRESTClient(agent2ControllerApiUrl,agent1ControllerApiUrl)
        }else {
            didClient = await newDIDExchangeClient(verifierID,proverID)
        }

        assert.isNotNull(didClient)

        connections = await didClient.performDIDExchangeE2E()
        assert.isNotEmpty(connections)

        verifier = didClient.agent1
        prover = didClient.agent2
    })

    after(() => {
        didClient.destroy()
    })

    it("Verifier sends a request presentation to the Prover", async function() {
        let conn = await connection(verifier, connections[0])
        return verifier.presentproof.sendRequestPresentation({
            my_did: conn.MyDID,
            their_did: conn.TheirDID,
            request_presentation: {},
        })
    })

    it("Prover accepts a request and sends a presentation to the Verifier", async function() {
        let action = await getAction(prover)
        return prover.presentproof.acceptRequestPresentation({
            piid: action.piid,
            // TODO need to add presentation depends on [Issue #1749]
            presentation: {},
            body: {}
        })
    })

    it("Verifier accepts a presentation", async function() {
        let action = await getAction(verifier)
        return verifier.presentproof.acceptPresentation({
            piid: action.piid,
        })
    })
}

const retries = 15;

async function getAction(agent) {
    for (let i = 0; i < retries; i++) {
        let resp = await agent.presentproof.actions()
        if (resp.actions.length > 0) {
            return resp.actions[0]
        }

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