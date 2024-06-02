// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import "sync"

type latch struct {
	paused bool
	lock   sync.WaitGroup
}

func (l *latch) block() {
	if !l.paused {
		l.lock.Add(1)
		l.paused = true
	}
}

func (l *latch) unblock() {
	if l.paused {
		l.lock.Done()
		l.paused = false
	}
}

func (l *latch) wait() {
	l.lock.Wait()
}

func (l *latch) Close() {
	//l.lock.Done()
}
