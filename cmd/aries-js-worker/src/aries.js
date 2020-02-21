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

const { loadWorker } = require("worker_loader")

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
        if (topics.length == 0){
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
 * @param opts are framework initialization options.
 * @class
 */
export const Framework = class {
    constructor(opts) {
        return (async () => {
            return await Aries(opts);
        })();
    }
};


/**
 * Aries provides Aries SSI-agent functions.
 * @param opts initialization options.
 * @constructor
 */
const Aries = function(opts) {
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
             * @returns {Promise<String>}
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

        destroy: async function() {
            var response = await invoke(aw, pending,  "aries", "Stop", "{}", "timeout while stopping aries")
            aw.terminate()
            aw = null
            return response
        },

        startNotifier : function(callback, topics) {
            if (!callback){
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
                        console.log("stopped notifier for topics:", topics)
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

            return () => {quit = true}
        },

        didexchange: {
            pkgname: "didexchange",
            createInvitation: async function (text) {
                return invoke(aw, pending,  this.pkgname, "CreateInvitation", text, "timeout while creating invitation")
            },
            receiveInvitation: async function (text) {
                return invoke(aw, pending,  this.pkgname, "ReceiveInvitation", text, "timeout while receiving invitation")
            },
            acceptInvitation: async function (text) {
                return invoke(aw, pending,  this.pkgname, "AcceptInvitation", text, "timeout while accepting invitation")
            },
            acceptExchangeRequest: async function (text) {
                return invoke(aw, pending,  this.pkgname, "AcceptExchangeRequest", text, "timeout while accepting exchange request")
            },
            createImplicitInvitation: async function (text) {
                return invoke(aw, pending,  this.pkgname, "CreateImplicitInvitation", text, "timeout while creating implicit invitation")
            },
            removeConnection: async function (text) {
                return invoke(aw, pending,  this.pkgname, "RemoveConnection", text, "timeout while removing invitation")
            },
            queryConnectionByID: async function (text) {
                return invoke(aw, pending,  this.pkgname, "QueryConnectionByID", text, "timeout while querying connection by ID")
            },
            queryConnections: async function (text) {
                return invoke(aw, pending,  this.pkgname, "QueryConnections", text, "timeout while querying connections")
            }
        },

        messaging: {
            pkgname: "messaging",
            registeredServices: async function (text) {
                return invoke(aw, pending,  this.pkgname, "RegisteredServices", text, "timeout while getting list of registered services")
            },
            registerMessageService: async function (text) {
                return invoke(aw, pending,  this.pkgname, "RegisterMessageService", text, "timeout while registering service")
            },
            registerHTTPMessageService: async function (text) {
                return invoke(aw, pending,  this.pkgname, "RegisterHTTPMessageService", text, "timeout while registering HTTP service")
            },
            unregisterMessageService: async function (text) {
                return invoke(aw, pending,  this.pkgname, "UnregisterMessageService", text, "timeout while unregistering service")
            },
            sendNewMessage: async function (text) {
                return invoke(aw, pending,  this.pkgname, "SendNewMessage", text, "timeout while sending new message")
            },
            sendReplyMessage: async function (text) {
                return invoke(aw, pending,  this.pkgname, "SendReplyMessage", text, "timeout while sending reply message")
            }
        },

        vdri: {
            pkgname: "vdri",
            createPublicDID: async function (text) {
                return invoke(aw, pending,  this.pkgname, "CreatePublicDID", text, "timeout while creating public DID")
            },
        },

        router: {
            pkgname: "router",
            register: async function (text) {
                return invoke(aw, pending,  this.pkgname, "Register", text, "timeout while registering router")
            },
            unregister: async function () {
                return invoke(aw, pending,  this.pkgname, "Unregister", "{}", "timeout while registering router")
            },
            getConnection: async function () {
                return invoke(aw, pending,  this.pkgname, "GetConnection", "{}", "timeout while fetching router connection id")
            }
        },

        verifiable: {
            pkgname: "verifiable",
            validateCredential: async function (text) {
                return invoke(aw, pending,  this.pkgname, "ValidateCredential", text, "timeout while validating verifiable credential")
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
        notifications.set("wasm-ready", async (result) => {
            clearTimeout(timer)
            invoke(aw, pending, "aries", "Start", opts, "timeout while starting aries").then(
                resp => resolve(),
                err => reject(new Error(err.message))
            )
            resolve(instance)
        })
    })
}
