/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict'

const inNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null
const inBrowser = typeof window !== 'undefined' && typeof window.document !== 'undefined';

// wait for 'notifierWait' milliseconds before retrying to check for incoming notifications
const notifierWait = 10000

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
        const timer = setTimeout(_ => reject(new Error(msgTimeout)), 5000)
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

async function waitForNotification(notifications, topics) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(_ => resolve(), notifierWait)
        // subscribe for all by default if topics not provided
        if (topics.length == 0) {
            topics = ["all"]
        }
        topics.forEach(function (topic, index) {
            notifications.set(topic, result => {
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
 *      "agent-rest-wshook": "ws://controller.api.example.com"
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

            var quit = false

            async function* run() {
                while (true) {
                    if (quit) {
                        //before stop, remove all topics
                        topics.forEach(function (item, index) {
                            notifications.delete(item)
                        });
                        return
                    }
                    yield await waitForNotification(notifications, topics)
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
             * Registers a http-over-didcomm service.
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
        vdri: {
            pkgname: "vdri",

            /**
             * Creates a new Public DID.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            createPublicDID: async function (req) {
                return invoke(aw, pending, this.pkgname, "CreatePublicDID", req, "timeout while creating public DID")
            },

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
             * Retrieves a did document.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            getDID: async function (req) {
                return invoke(aw, pending, this.pkgname, "GetDID", req, "timeout while retrieving did document")
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
        router: {
            pkgname: "router",

            /**
             * Registers an agent with the router.
             *
             * @param req - json document
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
            unregister: async function () {
                return invoke(aw, pending, this.pkgname, "Unregister", "{}", "timeout while registering router")
            },

            /**
             * Retrieves the router connection id.
             *
             * @returns {Promise<Object>}
             */
            getConnection: async function () {
                // console.log("router get connection")
                return invoke(aw, pending, this.pkgname, "Connection", "{}", "timeout while fetching router connection id")
            }
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
             * Generates a verifiable presentation from a verifiable credential.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            generatePresentation: async function (req) {
                return invoke(aw, pending,  this.pkgname, "GeneratePresentation", req, "timeout while generating verifiable presentation")
            },

            /**
             * Generates a verifiable presentation from a stored verifiable credential.
             *
             * @param req - json document
             * @returns {Promise<Object>}
             */
            generatePresentationByID: async function (req) {
                return invoke(aw, pending,  this.pkgname, "GeneratePresentationByID", req, "timeout while generating verifiable presentation by id")
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
            createKeySet: async function () {
                return invoke(aw, pending, this.pkgname, "CreateKeySet", {}, "timeout while creating key set")
            },
        }
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
        const timer = setTimeout(_ => reject(new Error("timout waiting for aries to initialize")), 10000)
        notifications.set("asset-ready", async (result) => {
            clearTimeout(timer)
            invoke(aw, pending, "aries", "Start", opts, "timeout while starting aries").then(
                resp => resolve(instance),
                err => reject(new Error(err.message))
            )
        })
    })
}
