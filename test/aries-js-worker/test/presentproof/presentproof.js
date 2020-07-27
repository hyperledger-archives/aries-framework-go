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
const actionsTopic = "present-proof_actions"
const statesTopic = "present-proof_states"
const stateDone = "done"

const presentation = {
    "presentations~attach": [{
        "lastmod_time": "0001-01-01T00:00:00Z",
        "data": {
            "base64": "ZXlKaGJHY2lPaUp1YjI1bElpd2lkSGx3SWpvaVNsZFVJbjAuZXlKcGMzTWlPaUprYVdRNlpYaGhiWEJzWlRwbFltWmxZakZtTnpFeVpXSmpObVl4WXpJM05tVXhNbVZqTWpFaUxDSnFkR2tpT2lKMWNtNDZkWFZwWkRvek9UYzRNelEwWmkwNE5UazJMVFJqTTJFdFlUazNPQzA0Wm1OaFltRXpPVEF6WXpVaUxDSjJjQ0k2ZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3ZNakF4T0M5amNtVmtaVzUwYVdGc2N5OTJNU0lzSW1oMGRIQnpPaTh2ZDNkM0xuY3pMbTl5Wnk4eU1ERTRMMk55WldSbGJuUnBZV3h6TDJWNFlXMXdiR1Z6TDNZeElsMHNJbWh2YkdSbGNpSTZJbVJwWkRwbGVHRnRjR3hsT21WaVptVmlNV1kzTVRKbFltTTJaakZqTWpjMlpURXlaV015TVNJc0ltbGtJam9pZFhKdU9uVjFhV1E2TXprM09ETTBOR1l0T0RVNU5pMDBZek5oTFdFNU56Z3RPR1pqWVdKaE16a3dNMk0xSWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFVISmxjMlZ1ZEdGMGFXOXVJaXdpUTNKbFpHVnVkR2xoYkUxaGJtRm5aWEpRY21WelpXNTBZWFJwYjI0aVhTd2lkbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpT201MWJHeDlmUS4="
        }
    }]
}

describe("Present Proof - The Verifier begins with a request presentation", async function () {
    describe(restMode, function () {
        presentProof(restMode)
    })
    describe(wasmMode, function () {
        presentProof(wasmMode)
    })
})

// scenarios
async function presentProof(mode) {
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

    let proverAction;
    it("Verifier sends a request presentation to the Prover", async function() {
        proverAction = getAction(prover)
        let conn = await connection(verifier, connections[0])
        return verifier.presentproof.sendRequestPresentation({
            my_did: conn.MyDID,
            their_did: conn.TheirDID,
            request_presentation: {will_confirm:true},
        })
    })

    let verifierAction;
    it("Prover accepts a request and sends a presentation to the Verifier", async function () {
        verifierAction = getAction(verifier)
        return prover.presentproof.acceptRequestPresentation({
            piid: (await proverAction).Properties.piid,
            presentation: presentation,
        })
    })

    const name = mode + ".js.presentation.test"

    it("Verifier accepts a presentation", async function () {
        return verifier.presentproof.acceptPresentation({
            piid: (await verifierAction).Properties.piid,
            names: [name],
        })
    })

    it("Verifier checks presentation", async function () {
        await getPresentation(verifier, name)
    })
}

async function getPresentation(agent, name) {
    await watchForEvent(agent, {
        topic: statesTopic,
        stateID: stateDone,
    })

    let res = await agent.verifiable.getPresentations()
    if (res.result) {
        for (let j = 0; j < res.result.length; j++) {
            if (res.result[j].name === name) {
                return
            }
        }
    }

    throw new Error("presentation not found")
}

async function getAction(agent) {
    return await watchForEvent(agent, {
        topic: actionsTopic,
    })
}

async function connection(agent, conn) {
    let res = await agent.didexchange.queryConnectionByID({
        id: conn
    })

    return res.result
}