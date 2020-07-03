/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
import {environment} from "../environment.js";
import {didExchangeClient, newDIDExchangeClient, newDIDExchangeRESTClient} from "../didexchange/didexchange_e2e.js";

const agent1ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.SECOND_USER_HOST}:${environment.SECOND_USER_API_PORT}`
const agent2ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`

const restMode = 'rest'
const wasmMode = 'wasm'
const retries = 10;

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
        request = await didexClient.agent1.outofband.createRequest(createRequest("Alice"))
    })

    it("Bob accepts the request and connects with Alice", async function () {
        let checked = checkConnection(mode, didexClient.agent1, didexClient.agent2, request.request['@id'])

        await didexClient.agent2.outofband.acceptRequest({
            my_label: "Bob",
            request: request.request,
        })

        await checked
    })
}

export function createRequest(label) {
    return {
        label: label,
        attachments: [
            {
                "@id": getRandom(1, 9) + "955adee-bdb4-437f-884a-b466e38d5884",
                description: "dummy",
                "mime-type": "text/plain",
                "lastmod_time": "0001-01-01T00:00:00Z",
                data: {"json": {}}
            }
        ]
    }
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
        let checked = checkConnection(mode, didexClient.agent1, didexClient.agent2, invitation.invitation['@id'])

        await didexClient.agent2.outofband.acceptInvitation({
            my_label: "Bob",
            invitation: invitation.invitation,
        })

        await checked
    })
}

async function client(mode) {
    if (mode === restMode) {
        return await newDIDExchangeRESTClient(agent2ControllerApiUrl, agent1ControllerApiUrl)
    }

    let client = await newDIDExchangeClient("alice", "bob")
    await client.setupRouter()
    return client
}

export async function checkConnection(mode, inviter, invitee, expected) {
    let connections = Promise.all([
        didExchangeClient.watchForConnection(inviter, "completed").then(async (id) => {
            let conn = await connection(inviter, id)
            assert.equal(expected, conn.InvitationID)
            return id
        }),
        didExchangeClient.watchForConnection(invitee, "completed").then(async (id) => {
            let conn = await connection(invitee, id)
            assert.equal(expected, conn.ParentThreadID)
            return id
        })
    ])

    if (mode === wasmMode) {
        didExchangeClient.acceptExchangeRequest(inviter)
    }

    return await connections
}

export async function connectAgents(mode, inviter, invitee) {
    let invitation = await inviter.outofband.createInvitation({
        label: getRandom(1, 10) + "_" + getRandom(1, 10),
    })

    let checked = checkConnection(mode, inviter, invitee, invitation.invitation['@id'])

    await invitee.outofband.acceptInvitation({
        my_label: getRandom(1, 10) + "_" + getRandom(1, 10),
        invitation: invitation.invitation,
    })

    return await checked
}

export function getRandom(min, max) {
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

export async function getAction(agent) {
    for (let i = 0; i < retries; i++) {
        let resp = await agent.outofband.actions()
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
