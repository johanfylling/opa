// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import (
	"context"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/ast/location"
	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/util/test"
)

func TestDebuggerAutomaticStop(t *testing.T) {
	tests := []struct {
		note          string
		props         LaunchProperties
		expEventType  EventType
		expEventIndex int
	}{
		{
			note:          "No automatic stop",
			expEventType:  TerminatedEventType,
			expEventIndex: 5,
		},
		{
			note: "Stop on entry",
			props: LaunchProperties{
				StopOnEntry: true,
			},
			expEventType:  StoppedEventType,
			expEventIndex: 1,
		},
		{
			note: "Stop on result",
			props: LaunchProperties{
				StopOnResult: true,
			},
			expEventType:  StoppedEventType,
			expEventIndex: 5,
		},
		{
			note: "Stop on fail",
			props: LaunchProperties{
				StopOnFail: true,
			},
			expEventType:  ExceptionEventType,
			expEventIndex: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			stk := newTestStack(testEvents...)

			eh := newTestEventHandler()
			l := logging.NewNoOpLogger()

			d := NewDebugger(ctx, SetLogger(l), SetEventHandler(eh.HandleEvent))
			thr := newThread(1, "test", stk, d.varManager, l)
			s := newSession(d, tc.props, []*thread{thr})
			s.start(ctx)

			test.EventuallyOrFatal(t, 5*time.Second, func() bool {
				e := eh.Next(10 * time.Millisecond)
				if e != nil && e.eventType == tc.expEventType {
					i, _ := stk.Current()
					return i == tc.expEventIndex
				}
				return false
			})
		})
	}
}

type testEvent struct {
	eventType EventType
	threadId  int
	text      string
}

type testEventHandler struct {
	ch chan *testEvent
}

func newTestEventHandler() *testEventHandler {
	return &testEventHandler{
		ch: make(chan *testEvent),
	}
}

func (teh *testEventHandler) HandleEvent(eventType EventType, threadId int, text string) {
	teh.ch <- &testEvent{
		eventType: eventType,
		threadId:  threadId,
		text:      text,
	}
}

func (teh *testEventHandler) Next(duration time.Duration) *testEvent {
	select {
	case e := <-teh.ch:
		return e
	case <-time.After(duration):
		return nil
	}
}

func (teh *testEventHandler) WaitFor(eventType EventType) *testEvent {
	for {
		e := <-teh.ch
		if e.eventType == eventType {
			return e
		}
	}
}

var testEvents = []*topdown.Event{
	{ // 0
		Op: topdown.EvalOp,
	},
	{ // 1
		Op: topdown.EnterOp,
		Location: &location.Location{
			File: "test.rego",
			Row:  1,
		},
	},
	{ // 2
		Op: topdown.EvalOp,
		Location: &location.Location{
			File: "test.rego",
			Row:  2,
		},
	},
	{ // 3
		Op: topdown.FailOp,
		Location: &location.Location{
			File: "test.rego",
			Row:  2,
		},
	},
	{ // 4
		Op: topdown.RedoOp,
		Location: &location.Location{
			File: "test.rego",
			Row:  2,
		},
	},
	{ // 5
		Op: topdown.ExitOp,
		Location: &location.Location{
			File: "test.rego",
			Row:  1,
		},
	},
}

type testStack struct {
	events []*topdown.Event
	index  int
	closed bool
}

func newTestStack(events ...*topdown.Event) stack {
	return &testStack{
		events: events,
	}
}

func (ts *testStack) Enabled() bool {
	return false
}

func (ts *testStack) TraceEvent(_ topdown.Event) {
}

func (ts *testStack) Config() topdown.TraceConfig {
	return topdown.TraceConfig{}
}

func (ts *testStack) Current() (int, *topdown.Event) {
	if ts.index >= len(ts.events) {
		return -1, nil
	}
	return ts.index, ts.events[ts.index]
}

func (ts *testStack) Event(i int) *topdown.Event {
	if ts.closed || i >= 0 && i < len(ts.events) {
		return ts.events[i]
	}
	return nil
}

func (ts *testStack) Next() (int, *topdown.Event) {
	if ts.closed || ts.index >= len(ts.events)-1 {
		return -1, nil
	}
	ts.index++
	return ts.Current()
}

func (ts *testStack) Result() rego.ResultSet {
	return nil
}

func (ts *testStack) Close() error {
	ts.closed = true
	return nil
}
