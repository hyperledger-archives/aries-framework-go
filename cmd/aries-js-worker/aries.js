/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict'

const _aries_isNodeJS = typeof module !== 'undefined' && module.exports

// TODO not all browsers support private members of classes
/* @class Aries provides Aries SSI-agent functions. */
const Aries = new function() {
    // TODO synchronize access on this map?
    this._pending = new Map()

    /**
     * Test methods.
     * TODO - remove. Used for testing.
     * @type {{_echo: (function(*=): Promise<String>)}}
     * @private
     */
    this._test = {

        /**
         * Returns the input text prepended with "echo: ".
         * TODO - remove.
         * @param text
         * @returns {Promise<String>}
         * @private
         */
        _echo: async function(text) {
            return Aries._invoke("test", "echo", text, "timeout while accepting invitation")
        }
    }

    this._newMsg = function(pkg, fn, payload) {
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

    this._invoke = async function(pkg, fn, arg, msgTimeout) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(_ => reject(new Error(msgTimeout)), 5000)
            const msg = Aries._newMsg(pkg, fn, arg)
            Aries._pending.set(msg.id, result => {
                clearTimeout(timer)
                if (result.isErr) {
                    reject(new Error(result.errMsg))
                }
                resolve(result.payload)
            })
            Aries._worker.postMessage(msg)
        })
    }

    this._getWorker = () => {
        if (_aries_isNodeJS) {
            const { Worker } = require('worker_threads')
            const worker = new Worker('./aries-worker-node.js')
            worker.on("message", result => {
                const cb = Aries._pending.get(result.id)
                Aries._pending.delete(result.id)
                cb(result)
            })
            return worker
        } else {
            const worker = new Worker('./aries-worker.js')
            worker.onmessage = e => {
                const result = e.data
                const cb = Aries._pending.get(result.id)
                Aries._pending.delete(result.id)
                cb(result)
            }
            return worker
        }
    }

    this._worker = this._getWorker()
}


if (_aries_isNodeJS) {
    module.exports.Aries = Aries
}
