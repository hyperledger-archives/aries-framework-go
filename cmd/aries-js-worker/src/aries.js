/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict'

const inNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null
const inBrowser = typeof window !== 'undefined' && typeof window.document !== 'undefined';

// wait for 'notifierWait' milliseconds before retrying to check for incoming notifications
const notifierWait = 10000

// time out for command operations
const commandTimeout = 25000

// base path to load assets from at runtime
const __publicPath = _ => {
    if (inNode) {
        // TODO determine module_path at runtime
        return process.cwd() + "/node_modules/@hyperledger/aries-framework-go/"
    } else if (inBrowser) {
        return "/aries-framework-go/"
    } else {
        // TODO #1127 - throw error or use default?
    }
}

__webpack_public_path__ = __publicPath()

const {loadWorker} = require("worker_loader")

// registers messages in pending and posts them to the worker
async function invoke(w, pending, pkg, fn, arg, msgTimeout) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(_ => reject(new Error(msgTimeout)), commandTimeout)
        let payload = arg
        if (typeof arg === "string") {
            payload = JSON.parse(arg)
        }
        const msg = newMsg(pkg, fn, payload)
        pending.set(msg.id, result => {
            clearTimeout(timer)
            if (result.isErr) {
                reject(new Error(result.errMsg))
            }
            resolve(result.payload)
        })
        w.postMessage(msg)
    })
}

async function waitForNotification(notifications, topics, key) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(_ => resolve(), notifierWait)
        // subscribe for all by default if topics not provided
        if (topics.length === 0) {
            topics = ["all"]
        }

        topics.forEach(function (topic, index) {
            if (notifications.get(topic) === undefined) {
                notifications.set(topic, new Map())
            }

            notifications.get(topic).set(key, result => {
                if (result.isErr) {
                    reject(new Error(result.errMsg))
                }
                resolve(result)
            })
        });
    });
}

function newMsg(pkg, fn, payload) {
    return {
        // TODO there are several approaches to generate random strings:
        // - which should we implement? do we need cryptographic-grade randomness for this?
        // - alternatively, should the generator be provided by the client?
        id: Math.random().toString(36).slice(2),
        pkg: pkg,
        fn: fn,
        payload: payload
    }
}

/**
 * Aries framework class provides Aries SSI-agent features.
 *
 * `opts` is an object with the framework's initialization options:
 *
 * {
 *      assetsPath: "/path/serving/the/framework/assets",
 *      "agent-default-label": "demo-js-agent",
 *      "http-resolver-url": ["https://uniresolver.io/1.0/identifiers"],
 *      "auto-accept": true,
 *      "outbound-transport": ["ws", "http"],
 *      "transport-return-route": "all",
 *      "log-level": "debug",
 *      "agent-rest-url": "http://controller.api.example.com",
 *      "agent-rest-wshook": "ws://controller.api.example.com",
 *      "context-provider-url": ["https://context-provider.example.com/ld_contexts.json"]
 *      "media-type-profiles": ["didcomm/v2"]
 * }
 *
 * @param opts framework initialization options.
 * @class
 */
export const Framework = class {
    constructor(opts) {
        return Aries(opts)
    }
};


/**
 * Aries provides Aries SSI-agent functions.
 * @param opts initialization options.
 * @constructor
 */
const Aries = function (opts) {
    if (!opts) {
        throw new Error("aries: missing options")
    }

    if (!opts.assetsPath) {
        throw new Error("aries: missing assets path")
    }

    // TODO synchronized access
    const notifications = new Map()
    const pending = new Map()

    const instance = {
        /**
         * Test methods.
         * TODO - remove. Used for testing.
         * @type {{_echo: (function(*=): Promise<String>)}}
         * @private
         */
        _test: {
            /**
             * Returns the input text prepended with "echo: ".
             * TODO - remove.
             * @param text
             * @returns {Promise<Object>}
             * @private
             */
            _echo: async function (text) {
                return new Promise((resolve, reject) => {
                    invoke(aw, pending, "test", "echo", {"echo": text}, "_echo() timed out").then(
                        resp => resolve(resp.echo),
                        err => reject(new Error("aries: _echo() failed. error: " + err.message))
                    )
                })
            }

        },

        destroy: async function () {
            var response = await invoke(aw, pending, "aries", "Stop", "{}", "timeout while stopping aries")
            aw.terminate()
            aw = null
            return response
        },

        startNotifier: function (callback, topics) {
            if (!callback) {
                console.error("callback is required to start notifier")
                return
            }

            let key = Math.random()
            let quit = false

            async function* run() {
                while (true) {
                    if (quit) {
                        //before stop, remove all topics
                        topics.forEach(function (item) {
                            notifications.get(item).delete(key)
                        });

                        return
                    }
                    yield await waitForNotification(notifications, topics, key)
                }
            }

            const cb = callback
            const asyncIterator = run();

            (async () => {
                for await (const val of asyncIterator) {
                    if (val) {
                        cb(val)
                    }
                }
            })();

            return () => {
                quit = true
            }
        },

        /**
         * Introduce methods - Refer to [OpenAPI spec](docs/rest/openapi_spec.md#generate-openapi-spec) for
         * input params and output return json values.
         */
        introduce: {
            pkgname: "introduce",
            /**
             * Actions returns pending actions that have not yet to be executed or canceled.
             *
             * @returns {Promise<Object>}
             */
            actions: async function () {
                return invoke(aw, pending, this.pkgname, "Actions", null, "timeout while getting actions")
            },

            /**
             * Accepts a problem report.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptProblemReport: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptProblemReport", req, "timeout while accepting a problem report")
            },

            /**
             * SendProposal sends a proposal to the introducees (the client has not published an out-of-band message).
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            sendProposal: function (req) {
                return invoke(aw, pending, this.pkgname, "SendProposal", req, "timeout while sending a proposal")
            },

            /**
             * SendProposalWithOOBInvitation sends a proposal to the introducee (the client has published an out-of-band invitation).
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            sendProposalWithOOBInvitation: function (req) {
                return invoke(aw, pending, this.pkgname, "SendProposalWithOOBInvitation", req, "timeout while sending a proposal with OOB invitation")
            },

            /**
             * SendRequest sends a request. Sending a request means that the introducee is willing to share their own out-of-band message.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            sendRequest: function (req) {
                return invoke(aw, pending, this.pkgname, "SendRequest", req, "timeout while sending a request")
            },

            /**
             * AcceptProposalWithOOBRequest is used when introducee wants to provide an out-of-band request.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptProposalWithOOBInvitation: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptProposalWithOOBInvitation", req, "timeout while accepting a proposal with OOBInvitation")
            },

            /**
             * AcceptProposal is used when introducee wants to accept a proposal without providing a OOBRequest.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptProposal: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptProposal", req, "timeout while accepting a proposal")
            },


            /**
             * AcceptRequestWithPublicOOBRequest is used when introducer wants to provide a published out-of-band request.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptRequestWithPublicOOBInvitation: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptRequestWithPublicOOBInvitation", req, "timeout while accepting a request with public OOBInvitation")
            },

            /**
             * AcceptRequestWithRecipients is used when the introducer does not have a published out-of-band message on hand
             * but he is willing to introduce agents to each other.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptRequestWithRecipients: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptRequestWithRecipients", req, "timeout while accepting a request with recipients")
            },

            /**
             * DeclineProposal is used to reject the proposal.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            declineProposal: function (req) {
                return invoke(aw, pending, this.pkgname, "DeclineProposal", req, "timeout while declining a proposal")
            },

            /**
             * DeclineRequest is used to reject the request.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            declineRequest: function (req) {
                return invoke(aw, pending, this.pkgname, "DeclineRequest", req, "timeout while declining a request")
            }
        },

        /**
         * Outofband methods - Refer to [OpenAPI spec](docs/rest/openapi_spec.md#generate-openapi-spec) for
         * input params and output return json values.
         */
        outofband: {
            pkgname: "outofband",
            /**
             * Actions returns pending actions that have not yet to be executed or canceled.
             *
             * @returns {Promise<Object>}
             */
            actions: async function () {
                return invoke(aw, pending, this.pkgname, "Actions", null, "timeout while getting actions")
            },

            /**
             * ActionContinue allows continuing with the protocol after an action event was triggered
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            actionContinue: async function (req) {
                return invoke(aw, pending, this.pkgname, "ActionContinue", req, "timeout action continue")
            },

            /**
             * ActionStop stops the protocol after an action event was triggered
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            actionStop: async function (req) {
                return invoke(aw, pending, this.pkgname, "ActionStop", req, "timeout action continue")
            },

            /**
             * CreateInvitation creates and saves an out-of-band invitation.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            createInvitation: async function (req) {
                return invoke(aw, pending, this.pkgname, "CreateInvitation", req, "timeout while creating an invitation")
            },

            /**
             * AcceptInvitation from another agent and return the ID of the new connection records.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptInvitation: async function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptInvitation", req, "timeout while accepting an invitation")
            },
        },

        /**
         * Issue Credential methods - Refer to [OpenAPI spec](docs/rest/openapi_spec.md#generate-openapi-spec) for
         * input params and output return json values.
         */
        issuecredential: {
            pkgname: "issuecredential",
            /**
             * Returns pending actions that have not yet to be executed or cancelled.
             *
             * @returns {Promise<Object>}
             */
            actions: async function () {
                return invoke(aw, pending, this.pkgname, "Actions", null, "timeout while getting actions")
            },
            /**
             * Sends an offer.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            sendOffer: async function (req) {
                return invoke(aw, pending, this.pkgname, "SendOffer", req, "timeout while sending an offer")
            },
            /**
             * Sends an offer V3.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            sendOfferV3: async function (req) {
                return invoke(aw, pending, this.pkgname, "SendOfferV3", req, "timeout while sending an offer")
            },
            /**
             * Sends a proposal.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            sendProposal: function (req) {
                return invoke(aw, pending, this.pkgname, "SendProposal", req, "timeout while sending a proposal")
            },
            /**
             * Sends a proposal v3.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            sendProposalV3: function (req) {
                return invoke(aw, pending, this.pkgname, "SendProposalV3", req, "timeout while sending a proposal")
            },
            /**
             * Sends a request.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            sendRequest: async function (req) {
                return invoke(aw, pending, this.pkgname, "SendRequest", req, "timeout while sending a request")
            },
            /**
             * Sends a request v3.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            sendRequestV3: async function (req) {
                return invoke(aw, pending, this.pkgname, "SendRequestV3", req, "timeout while sending a request")
            },
            /**
             * Accepts a proposal.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptProposal: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptProposal", req, "timeout while accepting a proposal")
            },
            /**
             * Accepts a proposal v3.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptProposalV3: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptProposalV3", req, "timeout while accepting a proposal")
            },
            /**
             * Declines a proposal.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            declineProposal: function (req) {
                return invoke(aw, pending, this.pkgname, "DeclineProposal", req, "timeout while declining a proposal")
            },
            /**
             * Accepts an offer.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptOffer: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptOffer", req, "timeout while accepting an offer")
            },
            /**
             * Accepts a problem report.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptProblemReport: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptProblemReport", req, "timeout while accepting a problem report")
            },
            /**
             * Declines an offer.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            declineOffer: function (req) {
                return invoke(aw, pending, this.pkgname, "DeclineOffer", req, "timeout while declining an offer")
            },
            /**
             * Is used when the Holder wants to negotiate about an offer he received.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            negotiateProposal: function (req) {
                return invoke(aw, pending, this.pkgname, "NegotiateProposal", req, "timeout while negotiating proposal")
            },
            /**
             * Is used when the Holder wants to negotiate about an offer he received.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            negotiateProposalV3: function (req) {
                return invoke(aw, pending, this.pkgname, "NegotiateProposalV3", req, "timeout while negotiating proposal")
            },
            /**
             * Accepts a request.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptRequest: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptRequest", req, "timeout while accepting a request")
            },
            /**
             * Accepts a request v3.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptRequestV3: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptRequestV3", req, "timeout while accepting a request")
            },
            /**
             * Declines a request.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            declineRequest: function (req) {
                return invoke(aw, pending, this.pkgname, "DeclineRequest", req, "timeout while declining a request")
            },
            /**
             * Accepts a credential.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptCredential: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptCredential", req, "timeout while accepting a credential")
            },
            /**
             * Declines a credential.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            declineCredential: function (req) {
                return invoke(aw, pending, this.pkgname, "DeclineCredential", req, "timeout while declining a credential")
            },
        },

        /**
         * Present Proof methods - Refer to [OpenAPI spec](docs/rest/openapi_spec.md#generate-openapi-spec) for
         * input params and output return json values.
         */
        presentproof: {
            pkgname: "presentproof",
            /**
             * Returns pending actions that have not yet to be executed or cancelled.
             *
             * @returns {Promise<Object>}
             */
            actions: async function () {
                return invoke(aw, pending, this.pkgname, "Actions", null, "timeout while getting actions")
            },
            /**
             * Sends a request presentation.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            sendRequestPresentation: async function (req) {
                return invoke(aw, pending, this.pkgname, "SendRequestPresentation", req, "timeout while sending a request presentation")
            },
            /**
             * Sends a request presentation v3.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            sendRequestPresentationV3: async function (req) {
                return invoke(aw, pending, this.pkgname, "SendRequestPresentationV3", req, "timeout while sending a request presentation")
            },
            /**
             * Sends a propose presentation.
             * https://w3c-ccg.github.io/universal-wallet-interop-spec/#proposepresentation
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            sendProposePresentation: function (req) {
                return invoke(aw, pending, this.pkgname, "SendProposePresentation", req, "timeout while sending a propose presentation")
            },
            /**
             * Sends a propose presentation v3.
             * https://w3c-ccg.github.io/universal-wallet-interop-spec/#proposepresentation
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            sendProposePresentationV3: function (req) {
                return invoke(aw, pending, this.pkgname, "SendProposePresentationV3", req, "timeout while sending a propose presentation")
            },
            /**
             * Accepts a problem report.
             * https://w3c-ccg.github.io/universal-wallet-interop-spec/#presentproof
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptProblemReport: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptProblemReport", req, "timeout while accepting a problem report")
            },
            /**
             * Accepts a request presentation.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptRequestPresentation: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptRequestPresentation", req, "timeout while accepting a request presentation")
            },
            /**
             * Accepts a request presentation v3.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptRequestPresentationV3: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptRequestPresentationV3", req, "timeout while accepting a request presentation")
            },
            /**
             * Accepts a propose presentation.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptProposePresentation: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptProposePresentation", req, "timeout while accepting a propose presentation")
            },
            /**
             * Accepts a propose presentation v3.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptProposePresentationV3: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptProposePresentationV3", req, "timeout while accepting a propose presentation")
            },
            /**
             * Accepts a presentation.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptPresentation: function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptPresentation", req, "timeout while accepting a presentation")
            },
            /**
             * Is used by the Prover to counter a presentation request they received with a proposal.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            negotiateRequestPresentation: function (req) {
                return invoke(aw, pending, this.pkgname, "NegotiateRequestPresentation", req, "timeout while negotiating a request presentation")
            },
            /**
             * Is used by the Prover to counter a presentation request v3 they received with a proposal v3.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            negotiateRequestPresentationV3: function (req) {
                return invoke(aw, pending, this.pkgname, "NegotiateRequestPresentationV3", req, "timeout while negotiating a request presentation")
            },
            /**
             * Declines a request presentation.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            declineRequestPresentation: function (req) {
                return invoke(aw, pending, this.pkgname, "DeclineRequestPresentation", req, "timeout while declining a request presentation")
            },
            /**
             * Declines a propose presentation.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            declineProposePresentation: function (req) {
                return invoke(aw, pending, this.pkgname, "DeclineProposePresentation", req, "timeout while declining a propose presentation")
            },
            /**
             * Declines a presentation.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            declinePresentation: function (req) {
                return invoke(aw, pending, this.pkgname, "DeclinePresentation", req, "timeout while declining a presentation")
            },
        },

        /**
         * DIDExchange methods - Refer to [OpenAPI spec](docs/rest/openapi_spec.md#generate-openapi-spec) for
         * input params and output return json values.
         */
        didexchange: {
            pkgname: "didexchange",

            /**
             * Creates a DID Exchange Invitation.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            createInvitation: async function (req) {
                return invoke(aw, pending, this.pkgname, "CreateInvitation", req, "timeout while creating invitation")
            },

            /**
             * Receives a DID Exchange invitation.
             *
             * @param invitation - json document
             * @returns {Promise<Object>}
             */
            receiveInvitation: async function (invitation) {
                return invoke(aw, pending, this.pkgname, "ReceiveInvitation", invitation, "timeout while receiving invitation")
            },

            /**
             * Accepts a DID Exchange invitation.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptInvitation: async function (req) {
                return new Promise((resolve, reject) => {
                    invoke(aw, pending, this.pkgname, "AcceptInvitation", req, "timeout while accepting invitation").then(
                        resp => resolve(resp),
                        err => reject(new Error("failed to accept invitation: " + err.message))
                    )
                })
            },

            /**
             * Accepts a DID Exchange request.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            acceptExchangeRequest: async function (req) {
                return invoke(aw, pending, this.pkgname, "AcceptExchangeRequest", req, "timeout while accepting exchange request")
            },

            /**
             * Creates an implicit invitation using inviter DID.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            createImplicitInvitation: async function (req) {
                return invoke(aw, pending, this.pkgname, "CreateImplicitInvitation", req, "timeout while creating implicit invitation")
            },

            /**
             * Saves a connection.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            createConnection: async function (req) {
                return invoke(aw, pending, this.pkgname, "CreateConnection", req, "timeout while creating connection")
            },

            /**
             * Removes a connection.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            removeConnection: async function (req) {
                return invoke(aw, pending, this.pkgname, "RemoveConnection", req, "timeout while removing invitation")
            },

            /**
             * Retrieves a connection by ID.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            queryConnectionByID: async function (req) {
                return invoke(aw, pending, this.pkgname, "QueryConnectionByID", req, "timeout while querying connection by ID")
            },

            /**
             * Retrieves connections based on search params.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            queryConnections: async function (req) {
                return invoke(aw, pending, this.pkgname, "QueryConnections", req, "timeout while querying connections")
            }
        },

        /*
        * Connection methods.
        */
        connection: {
            pkgname: "connection",

            createConnectionV2: async function (req) {
                return invoke(aw, pending, this.pkgname, "CreateConnectionV2", req, "timeout while creating didcomm v2 connection")
            },

            SetConnectionToDIDCommV2: async function (req) {
                return invoke(aw, pending, this.pkgname, "SetConnectionToDIDCommV2", req, "timeout while setting connection to didcomm v2")
            }
        },

        /**
         * DIDComm Messaging methods - Refer to [OpenAPI spec](docs/rest/openapi_spec.md#generate-openapi-spec) for
         * input params and output return json values.
         */
        messaging: {
            pkgname: "messaging",

            /**
             * Retrieves the list of registered service names.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            services: async function () {
                return invoke(aw, pending, this.pkgname, "Services", {}, "timeout while getting list of registered services")
            },

            /**
             * Registers a message service.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            registerService: async function (req) {
                return invoke(aw, pending, this.pkgname, "RegisterService", req, "timeout while registering service")
            },

            /**
             * Registers an http-over-didcomm service.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            registerHTTPService: async function (req) {
                return invoke(aw, pending, this.pkgname, "RegisterHTTPService", req, "timeout while registering HTTP service")
            },

            /**
             * Unregisters a message service.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            unregisterService: async function (req) {
                return invoke(aw, pending, this.pkgname, "UnregisterService", req, "timeout while unregistering service")
            },

            /**
             * Sends a message to destination.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            send: async function (req) {
                return invoke(aw, pending, this.pkgname, "Send", req, "timeout while sending new message")
            },

            /**
             * Sends a reply to an existing message.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            reply: async function (req) {
                return invoke(aw, pending, this.pkgname, "Reply", req, "timeout while sending reply message")
            }
        },

        /**
         * VDRI methods - Refer to [OpenAPI spec](docs/rest/openapi_spec.md#generate-openapi-spec) for
         * input params and output return json values.
         */
        vdr: {
            pkgname: "vdr",

            /**
             * Saves a did document.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            saveDID: async function (req) {
                return invoke(aw, pending, this.pkgname, "SaveDID", req, "timeout while saving did document")
            },

            /**
             * Create a did document.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            createDID: async function (req) {
                return invoke(aw, pending, this.pkgname, "CreateDID", req, "timeout while creating did document")
            },

            /**
             * Retrieves a did document.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            getDID: async function (req) {
                return invoke(aw, pending, this.pkgname, "GetDID", req, "timeout while retrieving did document")
            },

            /**
             * Resolve a did document.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            resolveDID: async function (req) {
                return invoke(aw, pending, this.pkgname, "ResolveDID", req, "timeout while resolving did document")
            },

            /**
             * Retrieves did records containing name and id.
             *
             * @returns {Promise<Object>}
             */
            getDIDRecords: async function () {
                return invoke(aw, pending, this.pkgname, "GetDIDRecords", {}, "timeout while retrieving did records")
            },
        },

        /**
         * Router methods - Refer to [OpenAPI spec](docs/rest/openapi_spec.md#generate-openapi-spec) for
         * input params and output return json values.
         */
        mediator: {
            pkgname: "mediator",

            /**
             * Registers an agent with the router.
             *
             * @param req - json document containing connection ID
             * @returns {Promise<Object>}
             */
            register: async function (req) {
                return invoke(aw, pending, this.pkgname, "Register", req, "timeout while registering router")
            },

            /**
             * Unregisters an agent with the router.
             *
             * @returns {Promise<Object>}
             */
            unregister: async function (req) {
                return invoke(aw, pending, this.pkgname, "Unregister", req, "timeout while registering router")
            },

            /**
             * Retrieves the router connection id.
             *
             * @returns {Promise<Object>}
             */
            getConnections: async function () {
                // console.log("router get connection")
                return invoke(aw, pending, this.pkgname, "Connections", "{}", "timeout while fetching router connection id")
            },

            /**
             * Reconnects an agent with the router.
             *
             * @param req - json document containing connection ID
             * @returns {Promise<Object>}
             */
            reconnect: async function (req) {
                return invoke(aw, pending, this.pkgname, "Reconnect", req, "timeout while reconnecting to router")
            },

            /**
             * Status returns details of pending messages from router for given connection.
             *
             * @param req - json document containing connection ID
             * @returns {Promise<Object>}
             */
            status: async function (req) {
                return invoke(aw, pending, this.pkgname, "Status", req, "timeout while getting status from router")
            },

            /**
             * batchPickup dispatches pending messages for given connection.
             *
             * @param req - json document containing connection ID and batch size
             * @returns {Promise<Object>}
             */
            batchPickup: async function (req) {
                return invoke(aw, pending, this.pkgname, "BatchPickup", req, "timeout while performing batch pickup from router")
            },

            /**
             * reconnectAll re-establishes all agent to mediator network connections.
             *
             * @returns {Promise<Object>}
             */
            reconnectAll: async function () {
                return invoke(aw, pending, this.pkgname, "ReconnectAll", {}, "timeout while reconnecting to mediator")
            },
        },

        /**
         * Verifiable methods related to credentials and presentations - Refer to [OpenAPI spec](docs/rest/openapi_spec.md#generate-openapi-spec) for
         * input params and output return json values.
         */
        verifiable: {
            pkgname: "verifiable",

            /**
             * Validates a verifiable credential.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            validateCredential: async function (req) {
                return invoke(aw, pending, this.pkgname, "ValidateCredential", req, "timeout while validating verifiable credential")
            },

            /**
             * Saves a verifiable credential.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            saveCredential: async function (req) {
                return invoke(aw, pending, this.pkgname, "SaveCredential", req, "timeout while saving verifiable credential")
            },

            /**
             * Retrieves a verifiable credential.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            getCredential: async function (req) {
                return invoke(aw, pending, this.pkgname, "GetCredential", req, "timeout while retrieving verifiable credential")
            },

            /**
             * Retrieves a verifiable credential by name.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            getCredentialByName: async function (req) {
                return invoke(aw, pending, this.pkgname, "GetCredentialByName", req, "timeout while retrieving verifiable credential by name")
            },

            /**
             * Retrieves verifiable credential records containing name and id.
             *
             * @returns {Promise<Object>}
             */
            getCredentials: async function () {
                return invoke(aw, pending, this.pkgname, "GetCredentials", {}, "timeout while retrieving verifiable credentials")
            },

            /**
             * Signs and adds proof to given credential using provided proof options
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            signCredential: async function (req) {
                return invoke(aw, pending, this.pkgname, "SignCredential", req, "timeout while adding proof to credential")
            },

            /**
             *  Derives a given verifiable credential for selective disclosure and returns it in response body.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            deriveCredential: async function (req) {
                return invoke(aw, pending, this.pkgname, "DeriveCredential", req, "timeout while deriving credential")
            },

            /**
             * Generates a verifiable presentation from a verifiable credential.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            generatePresentation: async function (req) {
                return invoke(aw, pending, this.pkgname, "GeneratePresentation", req, "timeout while generating verifiable presentation")
            },

            /**
             * Generates a verifiable presentation from a stored verifiable credential.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            generatePresentationByID: async function (req) {
                return invoke(aw, pending, this.pkgname, "GeneratePresentationByID", req, "timeout while generating verifiable presentation by id")
            },

            /**
             * Saves a presentation.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            savePresentation: async function (req) {
                return invoke(aw, pending, this.pkgname, "SavePresentation", req, "timeout while saving presentation")
            },

            /**
             * Retrieves a presentation.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            getPresentation: async function (req) {
                return invoke(aw, pending, this.pkgname, "GetPresentation", req, "timeout while retrieving presentation")
            },

            /**
             * Retrieves presentation records containing name and fields of interest.
             *
             * @returns {Promise<Object>}
             */
            getPresentations: async function () {
                return invoke(aw, pending, this.pkgname, "GetPresentations", {}, "timeout while retrieving presentations")
            },
        },

        /**
         * Key Management Service - Refer to [OpenAPI spec](docs/rest/openapi_spec.md#generate-openapi-spec) for
         * input params and output return json values.
         */
        kms: {
            pkgname: "kms",

            /**
             * Create key set.
             *
             * @returns {Promise<Object>}
             */
            createKeySet: async function (req) {
                return invoke(aw, pending, this.pkgname, "CreateKeySet", req, "timeout while creating key set")
            },

            /**
             * Import key.
             *
             * @returns {Promise<Object>}
             */
            importKey: async function (req) {
                return invoke(aw, pending, this.pkgname, "ImportKey", req, "timeout while importing key")
            },
        },
        /**
         * Verifiable Credential Wallet based on Universal Wallet 2020 https://w3c-ccg.github.io/universal-wallet-interop-spec/#interface
         *
         * Refer to [OpenAPI spec](docs/rest/openapi_spec.md#generate-openapi-spec) for
         * input params and output return json values.
         */
        vcwallet: {
            pkgname: "vcwallet",

            /**
             * Creates new wallet profile and returns error if wallet profile is already created.
             *
             * @returns {Promise<Object>}
             */
            createProfile: async function (req) {
                return invoke(aw, pending, this.pkgname, "CreateProfile", req, "timeout while creating wallet profile")
            },

            /**
             * Updates an existing wallet profile and returns error if profile doesn't exists.
             *
             * @returns {Promise<Object>}
             */
            updateProfile: async function (req) {
                return invoke(aw, pending, this.pkgname, "UpdateProfile", req, "timeout while updating wallet profile")
            },

            /**
             * Checks if profile exists for given wallet user.
             *
             * @returns {Promise<Object>} - empty promise if found or error if not not found.
             */
            profileExists: async function (req) {
                return invoke(aw, pending, this.pkgname, "ProfileExists", req, "timeout while checking if profile exists")
            },

            /**
             * Unlocks given wallet's key manager instance & content store and
             * returns a authorization token to be used for performing wallet operations.
             *
             * @returns {Promise<Object>}
             */
            open: async function (req) {
                return invoke(aw, pending, this.pkgname, "Open", req, "timeout while opening wallet")
            },

            /**
             * Expires token issued to this VC wallet, removes wallet's key manager instance and closes wallet content store.
             *
             * returns response containing bool flag false if token is not found or already expired for this wallet user.
             *
             * @returns {Promise<Object>}
             */
            close: async function (req) {
                return invoke(aw, pending, this.pkgname, "Close", req, "timeout while closing wallet")
            },

            /**
             * adds given data model to wallet content store.
             *
             * Supported data models:
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Key
             *
             * @returns {Promise<Object>}
             */
            add: async function (req) {
                return invoke(aw, pending, this.pkgname, "Add", req, "timeout while adding content to wallet")
            },

            /**
             * removes given content from wallet content store.
             *
             * Supported data models:
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
             *
             * @returns {Promise<Object>}
             */
            remove: async function (req) {
                return invoke(aw, pending, this.pkgname, "Remove", req, "timeout while removing content from wallet")
            },

            /**
             * gets content from wallet content store.
             *
             * Supported data models:
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
             *
             * @returns {Promise<Object>}
             */
            get: async function (req) {
                return invoke(aw, pending, this.pkgname, "Get", req, "timeout while getting content from wallet")
            },

            /**
             * gets all contents from wallet content store for given content type.
             *
             * Supported data models:
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
             *    - https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
             *
             * @returns {Promise<Object>}
             */
            getAll: async function (req) {
                return invoke(aw, pending, this.pkgname, "GetAll", req, "timeout getting all contents wallet")
            },

            /**
             *
             * runs query against wallet credential contents and returns presentation containing credential results.
             *
             * This function may return multiple presentations as a result based on combination of query types used.
             *
             * https://w3c-ccg.github.io/universal-wallet-interop-spec/#query
             *
             * Supported Query Types:
             *    - https://www.w3.org/TR/json-ld11-framing
             *    - https://identity.foundation/presentation-exchange
             *    - https://w3c-ccg.github.io/vp-request-spec/#query-by-example
             *    - https://w3c-ccg.github.io/vp-request-spec/#did-authentication-request
             *
             * @returns {Promise<Object>}
             */
            query: async function (req) {
                return invoke(aw, pending, this.pkgname, "Query", req, "timeout while querying wallet")
            },

            /**
             *
             * adds proof to a Verifiable Credential.
             *
             * https://w3c-ccg.github.io/universal-wallet-interop-spec/#issue
             *
             * @returns {Promise<Object>}
             */
            issue: async function (req) {
                return invoke(aw, pending, this.pkgname, "Issue", req, "timeout while issuing from wallet")
            },

            /**
             *
             * produces a Verifiable Presentation.
             *
             * https://w3c-ccg.github.io/universal-wallet-interop-spec/#prove
             *
             * @returns {Promise<Object>}
             */
            prove: async function (req) {
                return invoke(aw, pending, this.pkgname, "Prove", req, "timeout while proving from wallet")
            },

            /**
             *
             * verifies a Verifiable Credential or a Verifiable Presentation.
             *
             * https://w3c-ccg.github.io/universal-wallet-interop-spec/#prove
             *
             * @returns {Promise<Object>}
             */
            verify: async function (req) {
                return invoke(aw, pending, this.pkgname, "Verify", req, "timeout while verifying from wallet")
            },

            /**
             *
             * derives a Verifiable Credential.
             *
             * https://w3c-ccg.github.io/universal-wallet-interop-spec/#derive
             *
             * @returns {Promise<Object>}
             */
            derive: async function (req) {
                return invoke(aw, pending, this.pkgname, "Derive", req, "timeout while deriving from wallet")
            },

            /**
             *
             * creates a key pair from wallet.
             *
             * @returns {Promise<Object>}
             */
            createKeyPair: async function (req) {
                return invoke(aw, pending, this.pkgname, "CreateKeyPair", req, "timeout while creating key pair from wallet")
            },

            /**
             *
             * accepts out-of-band invitation and performs DID exchange from wallet.
             *
             * @returns {Promise<Object>}
             */
            connect: async function (req) {
                return invoke(aw, pending, this.pkgname, "Connect", req, "timeout while performing DID connect from wallet")
            },

            /**
             *
             * accepts out-of-band invitation and sends propose presentation message to sender.
             *
             *  Returns request presentation message response.
             *
             * @returns {Promise<Object>}
             */
            proposePresentation: async function (req) {
                return invoke(aw, pending, this.pkgname, "ProposePresentation", req, "timeout while proposing presentation from wallet")
            },

            /**
             *
             * sends presentation as present proof message.
             *
             * @returns {Promise<Object>}
             */
            presentProof: async function (req) {
                return invoke(aw, pending, this.pkgname, "PresentProof", req, "timeout while performing present proof from wallet")
            },

            /**
             *
             * accepts out-of-band invitation, sends propose credential message from wallet to issuer and optionally waits for offer credential response.
             *
             *  Returns offer credential message response.
             *
             * @returns {Promise<Object>}
             */
            proposeCredential: async function (req) {
                return invoke(aw, pending, this.pkgname, "ProposeCredential", req, "timeout while proposing credential from wallet")
            },

            /**
             *
             * sends request credential message from wallet to issuer and optionally waits for credential fulfillment.
             *
             *  Returns credential fulfillment and web redirect info.
             *
             * @returns {Promise<Object>}
             */
            requestCredential: async function (req) {
                return invoke(aw, pending, this.pkgname, "RequestCredential", req, "timeout while performing request credential from wallet")
            },
        },
        /**
         * JSON-LD management API.
         *
         * Refer to [OpenAPI spec](docs/rest/openapi_spec.md#generate-openapi-spec) for
         * input params and output return json values.
         */
        ld: {
            pkgname: "ld",

            /**
             * Adds JSON-LD contexts to the underlying storage.
             *
             * @returns {Promise<Object>}
             */
            addContexts: async function (req) {
                return invoke(aw, pending, this.pkgname, "AddContexts", req, "timeout while adding contexts")
            },

            /**
             * Adds remote provider and JSON-LD contexts from that provider to the underlying storage.
             *
             * @returns {Promise<Object>}
             */
            addRemoteProvider: async function (req) {
                return invoke(aw, pending, this.pkgname, "AddRemoteProvider", req, "timeout while adding remote provider")
            },

            /**
             * Updates contexts from the remote provider.
             *
             * @returns {Promise<Object>}
             */
            refreshRemoteProvider: async function (req) {
                return invoke(aw, pending, this.pkgname, "RefreshRemoteProvider", req, "timeout while refreshing remote provider")
            },

            /**
             * Deletes remote provider and JSON-LD contexts from that provider from the underlying storage.
             *
             * @returns {Promise<Object>}
             */
            deleteRemoteProvider: async function (req) {
                return invoke(aw, pending, this.pkgname, "DeleteRemoteProvider", req, "timeout while removing remote provider")
            },

            /**
             * Gets all remote providers from the underlying storage.
             *
             * @returns {Promise<Object>}
             */
            getAllRemoteProviders: async function () {
                return invoke(aw, pending, this.pkgname, "GetAllRemoteProviders", {}, "timeout while getting remote providers")
            },

            /**
             * Updates contexts from all remote providers in the underlying storage.
             *
             * @returns {Promise<Object>}
             */
            refreshAllRemoteProviders: async function (req) {
                return invoke(aw, pending, this.pkgname, "RefreshAllRemoteProviders", req, "timeout while refreshing remote providers")
            },
        },
    }

    // start aries worker
    var aw = loadWorker(
        pending,
        notifications,
        {
            dir: opts.assetsPath,
            wasm: opts.assetsPath + "/aries-js-worker.wasm",
            wasmJS: opts.assetsPath + "/wasm_exec.js"
        }
    )

    // return promise which waits for worker to load and aries to start.
    return new Promise((resolve, reject) => {
        const timer = setTimeout(_ => reject(new Error("timout waiting for aries to initialize")), 15000)
        notifications.set("asset-ready", new Map().set("asset", async (result) => {
            clearTimeout(timer)
            invoke(aw, pending, "aries", "Start", opts, "timeout while starting aries").then(
                resp => resolve(instance),
                err => reject(new Error(err.message))
            )
        }))
    })
}
