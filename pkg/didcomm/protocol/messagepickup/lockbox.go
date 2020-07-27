/*
Reference implementation of kmutex from github.com/im7mortal/kmutex

SPDX-License-Identifier: Apache-2.0
*/

package messagepickup

import "sync"

type lockbox struct {
	c *sync.Cond
	l sync.Locker
	s map[interface{}]struct{}
}

func newLockBox() *lockbox {
	l := sync.Mutex{}
	return &lockbox{c: sync.NewCond(&l), l: &l, s: make(map[interface{}]struct{})}
}

func (km *lockbox) locked(key interface{}) (ok bool) { _, ok = km.s[key]; return }

// Unlock lockbox by unique ID.
func (km *lockbox) Unlock(key interface{}) {
	km.l.Lock()
	defer km.l.Unlock()
	delete(km.s, key)
	km.c.Broadcast()
}

// Lock lockbox by unique ID.
func (km *lockbox) Lock(key interface{}) {
	km.l.Lock()
	defer km.l.Unlock()

	for km.locked(key) {
		km.c.Wait()
	}

	km.s[key] = struct{}{}
}
