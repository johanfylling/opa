// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/topdown"
)

type threadState interface{}

type eventHandler func(t *thread, e *topdown.Event, s threadState) (bool, threadState, error)

type thread struct {
	id              int
	name            string
	stack           stack
	eventHandler    eventHandler
	breakpointLatch latch
	stopped         bool
	state           threadState
	logger          logging.Logger
}

func newThread(id int, name string, stack stack, logger logging.Logger) *thread {
	return &thread{
		id:     id,
		name:   name,
		stack:  stack,
		logger: logger,
	}
}

func (t *thread) run(ctx context.Context) error {
	for {
		if t.stopped {
			return fmt.Errorf("thread stopped")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		t.logger.Debug("Waiting on breakpoint latch")
		t.breakpointLatch.wait()
		t.logger.Debug("Breakpoint latch released")

		err := t.stepIn()
		if err != nil {
			t.stopped = true
			return err
		}
	}
}

func (t *thread) current() (*topdown.Event, error) {
	_, e := t.stack.Current()
	return e, nil
}

func (t *thread) stepIn() error {
	if t.stopped {
		return fmt.Errorf("thread stopped")
	}

	_, e := t.stack.Next()
	if e == nil {
		return fmt.Errorf("end of stack")
	}

	br, s, err := t.eventHandler(t, e, t.state)
	if err != nil {
		return err
	}
	t.state = s

	if br {
		t.logger.Debug("Blocking breakpoint latch")
		t.breakpointLatch.block()
	}

	return nil
}

func (t *thread) stackEvents(from int) []*topdown.Event {
	var events []*topdown.Event
	for {
		e := t.stack.Get(from)
		if e == nil {
			break
		}
		events = append(events, e)
		from++
	}
	return events
}

func (t *thread) stop() {
	t.stopped = true
}

func (t *thread) done() bool {
	return t.stopped || !t.stack.Enabled()
}
