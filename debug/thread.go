// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import (
	"context"
	"fmt"
)

type thread struct {
	id              int
	name            string
	breakpointLatch latch
	stopped         bool
}

func newThread(id int, name string) *thread {
	return &thread{
		id:   id,
		name: name,
	}
}

func (t *thread) run(ctx context.Context) error {
	for {
		if t.stopped {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		t.breakpointLatch.wait()
		err := t.stepIn()
		if err != nil {
			t.stopped = true
			return err
		}
	}
}

func (t *thread) stepIn() error {
	if t.stopped {
		return fmt.Errorf("thread stopped")
	}

	return fmt.Errorf("step-in not supported")
}

func (t *thread) stop() {
	t.stopped = true
}
