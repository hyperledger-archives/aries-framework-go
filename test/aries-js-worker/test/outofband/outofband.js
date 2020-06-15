/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
import {environment} from "../environment.js";
import {newDIDExchangeClient, newDIDExchangeRESTClient} from "../didexchange/didexchange_e2e.js";

const agent1ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.SECOND_USER_HOST}:${environment.SECOND_USER_API_PORT}`
const agent2ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`

const restMode = 'rest'
const wasmMode = 'wasm'

describe("Outofband - New connection after Alice sends an out-of-band request to Bob", async function () {
    describe(restMode, function () {
        outofbandRequest(restMode)
    })
    describe(wasmMode, function () {
        outofbandRequest(wasmMode)
    })
})

describe("Outofband - New connection after Alice sends an ouf-of-band invitation to Bob", async function () {
    describe(restMode, function () {
        outofbandInvitation(restMode)
    })
    describe(wasmMode, function () {
        outofbandInvitation(wasmMode)
    })
})

async function outofbandRequest(mode) {
    let didexClient

    before(async () => {
        didexClient = await client(mode)
    })

    after(() => {
        didexClient.destroy()
    })

    let request;
    it("Alice constructs an out-of-band request with no attachments", async function () {
        request = await didexClient.agent1.outofband.createRequest({
            label: "Alice",
            attachments: [
                {
                    "@id": getRandom(1, 9) + "955adee-bdb4-437f-884a-b466e38d5884",
                    description: "dummy",
                    "mime-type": "text/plain",
                    "lastmod_time": "0001-01-01T00:00:00Z",
                    data: {"json": {}}
                }
            ]
        })
    })

    it("Bob accepts the request and connects with Alice", async function () {
        didexClient.agent2.outofband.acceptRequest({
            my_label: "Bob",
            request: request.request,
        })

        await checkConnection(mode, didexClient, request.request['@id'])
    })
}

async function outofbandInvitation(mode) {
    let didexClient

    before(async () => {
        didexClient = await client(mode)
    })

    after(() => {
        didexClient.destroy()
    })

    let invitation;
    it("Alice constructs an out-of-band invitation", async function () {
        invitation = await didexClient.agent1.outofband.createInvitation({
            label: "Alice"
        })
    })

    it("Bob accepts the invitation and connects with Alice", async function () {
        didexClient.agent2.outofband.acceptInvitation({
            my_label: "Bob",
            invitation: invitation.invitation,
        })

        await checkConnection(mode, didexClient, invitation.invitation['@id'])
    })
}

async function client(mode) {
    if (mode === restMode) {
        return await newDIDExchangeRESTClient(agent2ControllerApiUrl, agent1ControllerApiUrl)
    }

    return await newDIDExchangeClient("alice", "bob")
}

async function checkConnection(mode, didexClient, expected) {
    if (mode === wasmMode) {
        let connID = didexClient.watchForConnection(didexClient.agent1, "requested")
        await didexClient.agent1.didexchange.acceptExchangeRequest({id: await connID})
    }

    return Promise.all([
        didexClient.watchForConnection(didexClient.agent1, "completed").then(async (id) => {
            let conn = await connection(didexClient.agent1, id)
            assert.equal(expected, conn.InvitationID)
        }),
        didexClient.watchForConnection(didexClient.agent2, "completed").then(async (id) => {
            let conn = await connection(didexClient.agent2, id)
            assert.equal(expected, conn.ParentThreadID)
        })
    ])
}

function getRandom(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

async function connection(agent, conn) {
    let res = await agent.didexchange.queryConnectionByID({
        id: conn
    })

    return res.result
}
