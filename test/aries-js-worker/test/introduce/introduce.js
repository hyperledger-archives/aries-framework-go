/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
import {environment} from "../environment.js";
import {newAries, newAriesREST} from "../common.js"
import {
    checkConnection,
    connectAgents,
    createRequest,
    getAction as getOutofbandAction
} from "../outofband/outofband.js";
import {didExchangeClient} from "../didexchange/didexchange_e2e.js";

const agent1ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.SECOND_USER_HOST}:${environment.SECOND_USER_API_PORT}`
const agent2ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`
const agent3ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.THIRD_USER_HOST}:${environment.THIRD_USER_API_PORT}`

const restMode = 'rest'
const wasmMode = 'wasm'
const retries = 10;

describe("Introduce - Alice has Carol's public out-of-band request", async function () {
    describe(restMode, function () {
        skipProposal(restMode)
    })
    describe(wasmMode, function () {
        skipProposal(wasmMode)
    })
})

describe("Introduce - Alice has Carol's public out-of-band request. The protocol starts with introduce request.", async function () {
    describe(restMode, function () {
        skipProposalWithRequest(restMode)
    })
    describe(wasmMode, function () {
        skipProposalWithRequest(wasmMode)
    })
})

describe("Introduce - Bob sends a response with approve and an out-of-band request.", async function () {
    describe(restMode, function () {
        proposal(restMode)
    })
    describe(wasmMode, function () {
        proposal(wasmMode)
    })
})

describe("Introduce - Bob sends a response with approve and an out-of-band request. The protocol starts with introduce request", async function () {
    describe(restMode, function () {
        proposalWithRequest(restMode)
    })
    describe(wasmMode, function () {
        proposalWithRequest(wasmMode)
    })
})

async function proposalWithRequest(mode) {
    let alice, bob, carol;
    before(async () => {
        [alice, bob, carol] = await createClients(mode)
    })

    after(async () => {
        await destroyClients(mode, alice, bob, carol)
    })

    let alice_bob, alice_carol;
    it("Bob and Carol have established connection with Alice", async function () {
        alice_bob = await connectAgents(mode, alice, bob)
        alice_carol = await connectAgents(mode, alice, carol)
    })

    it("Bob sends introduce request to the Alice asking about Carol", async function () {
        let conn = await bob.didexchange.queryConnectionByID({id: alice_bob[1]})
        await bob.introduce.sendRequest({
            "please_introduce_to": {"name": "Carol", "img~attach": {"content": {}}},
            "my_did": conn.result.MyDID,
            "their_did": conn.result.TheirDID
        })
    })

    let request;
    it("Alice sends introduce proposal back to the Bob and requested introduce", async function () {
        let conn = await alice.didexchange.queryConnectionByID({id: alice_carol[0]})

        let action = await getAction(alice)
        await alice.introduce.acceptRequestWithRecipients({
            piid: action.PIID,

            "recipient": {
                "to": {"name": "Bob", "img~attach": {"content": {}}},
                "my_did": conn.result.MyDID,
                "their_did": conn.result.TheirDID
            },
            "to": {"name": "Carol", "img~attach": {"content": {}}},
        })
    })

    it("Bob wants to know Carol and sends introduce response with approve and provides an out-of-band request", async function () {
        request = await bob.outofband.createRequest(createRequest("Bob"))
        let action = await getAction(bob)
        await bob.introduce.acceptProposalWithOOBRequest({
            piid: action.PIID,
            "request": request.request
        })
    })

    it("Carol wants to know Bob and sends introduce response with approve", async function () {
        let action = await getAction(carol)
        await carol.introduce.acceptProposal({
            piid: action.PIID,
        })
        action = await getOutofbandAction(carol)

        let checked = checkConnection(mode, bob, carol, request.request['@id'])

        await carol.outofband.actionContinue({
            piid: action.PIID,
            label: "Bob",
        })

        await checked
    })
}

async function proposal(mode) {
    let alice, bob, carol;
    before(async () => {
        [alice, bob, carol] = await createClients(mode)
    })

    after(async () => {
        await destroyClients(mode, alice, bob, carol)
    })

    let alice_bob, alice_carol;
    it("Bob and Carol have established connection with Alice", async function () {
        alice_bob = await connectAgents(mode, alice, bob)
        alice_carol = await connectAgents(mode, alice, carol)
    })

    let request;
    it("Alice sends introduce proposal to the Bob and Carol", async function () {
        let conn1 = await alice.didexchange.queryConnectionByID({id: alice_bob[0]})
        let conn2 = await alice.didexchange.queryConnectionByID({id: alice_carol[0]})
        await alice.introduce.sendProposal({
            "recipients": [
                {
                    "to": {"name": "Carol", "img~attach": {"content": {}}},
                    "my_did": conn1.result.MyDID,
                    "their_did": conn1.result.TheirDID
                },
                {
                    "to": {"name": "Bob", "img~attach": {"content": {}}},
                    "my_did": conn2.result.MyDID,
                    "their_did": conn2.result.TheirDID
                }
            ]
        })
    })

    it("Bob wants to know Carol and sends introduce response with approve and provides an out-of-band request", async function () {
        request = await bob.outofband.createRequest(createRequest("Bob"))
        let action = await getAction(bob)
        await bob.introduce.acceptProposalWithOOBRequest({
            piid: action.PIID,
            "request": request.request
        })
    })

    it("Carol wants to know Bob and sends introduce response with approve", async function () {
        let action = await getAction(carol)
        await carol.introduce.acceptProposal({
            piid: action.PIID,
        })
        action = await getOutofbandAction(carol)

        let checked = checkConnection(mode, bob, carol, request.request['@id'])

        await carol.outofband.actionContinue({
            piid: action.PIID,
            label: "Bob",
        })

        await checked
    })
}

async function skipProposalWithRequest(mode) {
    let alice, bob, carol;
    before(async () => {
        [alice, bob, carol] = await createClients(mode)
    })

    after(async () => {
        await destroyClients(mode, alice, bob, carol)
    })

    let alice_bob, alice_carol;
    it("Bob and Carol have established connection with Alice", async function () {
        alice_bob = await connectAgents(mode, alice, bob)
        alice_carol = await connectAgents(mode, alice, carol)
    })

    let request;
    it("Bob sends introduce request to the Alice asking about Carol", async function () {
        let conn = await bob.didexchange.queryConnectionByID({id: alice_bob[1]})
        await bob.introduce.sendRequest({
            "please_introduce_to": {"name": "Carol", "img~attach": {"content": {}}},
            "my_did": conn.result.MyDID,
            "their_did": conn.result.TheirDID
        })
    })

    it("Alice sends introduce proposal back to the requester with public out-of-band request", async function () {
        let action = await getAction(alice)
        request = await carol.outofband.createRequest(createRequest("Carol"))
        await alice.introduce.acceptRequestWithPublicOOBRequest({
            piid: action.PIID,
            "request": request.request, "to": {"name": "Carol", "img~attach": {"content": {}}}
        })
    })

    it("Bob wants to know Carol and sends introduce response with approve", async function () {
        let action = await getAction(bob)
        await bob.introduce.acceptProposal({
            piid: action.PIID,
        })
        action = await getOutofbandAction(bob)

        let checked = checkConnection(mode, carol, bob, request.request['@id'])

        await bob.outofband.actionContinue({
            piid: action.PIID,
            label: "Bob",
        })

        await checked
    })
}

async function skipProposal(mode) {
    let alice, bob, carol;
    before(async () => {
        [alice, bob, carol] = await createClients(mode)
    })

    after(async () => {
        await destroyClients(mode, alice, bob, carol)
    })

    let alice_bob, alice_carol;
    it("Bob and Carol have established connection with Alice", async function () {
        alice_bob = await connectAgents(mode, alice, bob)
        alice_carol = await connectAgents(mode, alice, carol)
    })

    let request;
    it("Alice sends introduce proposal to the Bob with Carol out-of-band request", async function () {
        let conn = await alice.didexchange.queryConnectionByID({id: alice_bob[0]})
        request = await carol.outofband.createRequest(createRequest("Carol"))

        await alice.introduce.sendProposalWithOOBRequest({
            "request": request.request,
            "recipient": {
                "to": {"name": "Carol"},
                "my_did": conn.result.MyDID,
                "their_did": conn.result.TheirDID
            }
        })
    })

    it("Bob wants to know Carol and sends introduce response with approve", async function () {
        let action = await getAction(bob)
        await bob.introduce.acceptProposal({
            piid: action.PIID,
        })
        action = await getOutofbandAction(bob)

        let checked = checkConnection(mode, carol, bob, request.request['@id'])

        await bob.outofband.actionContinue({
            piid: action.PIID,
            label: "Bob",
        })

        await checked
    })
}

function clients(mode) {
    if (mode === restMode) {
        return Promise.all([
            newAriesREST(agent1ControllerApiUrl),
            newAriesREST(agent2ControllerApiUrl),
            newAriesREST(agent3ControllerApiUrl)
        ]);
    }

    return Promise.all([
        newAries("alice", "alice"),
        newAries("bob", "bob"),
        newAries("carol", "carol")
    ]);
}

async function createClients(mode) {
    let [alice, bob, carol] = await clients(mode)
    if (mode === wasmMode) {
        await didExchangeClient.addRouter(mode, alice)
        await didExchangeClient.addRouter(mode, bob)
        await didExchangeClient.addRouter(mode, carol)
    }

    return [alice, bob, carol]
}

async function destroyClients(mode, alice, bob, carol) {
    if (mode === wasmMode) {
        await alice.mediator.unregister()
        await bob.mediator.unregister()
        await carol.mediator.unregister()
    }

    await alice.destroy()
    await bob.destroy()
    await carol.destroy()
}

async function getAction(agent) {
    for (let i = 0; i < retries; i++) {
        let resp = await agent.introduce.actions()
        if (resp.actions.length > 0) {
            assert.isNotEmpty(resp.actions[0].MyDID)
            assert.isNotEmpty(resp.actions[0].TheirDID)

            return resp.actions[0]
        }

        await sleep(1000);
    }

    throw new Error("no action")
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
