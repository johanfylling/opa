// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import (
	"context"
	"fmt"
	"reflect"
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

	testEvents := []*topdown.Event{
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

	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			stk := newTestStack(testEvents...)
			eh := newTestEventHandler()
			_, s := setupDebuggerSession(ctx, stk, tc.props, eh.HandleEvent, nil)
			s.start(ctx)

			test.EventuallyOrFatal(t, 5*time.Second, func() bool {
				e := eh.Next(10 * time.Millisecond)
				if e != nil && e.Type == tc.expEventType {
					i, _ := stk.Current()
					return i == tc.expEventIndex
				}
				return false
			})
		})
	}
}

func TestDebuggerStopOnBreakpoint(t *testing.T) {
	tests := []struct {
		note            string
		breakpoint      location.Location
		events          []*topdown.Event
		expEventIndices []int
	}{
		{
			note:       "breakpoint on line with single event",
			breakpoint: location.Location{File: "test.rego", Row: 1},
			events: []*topdown.Event{
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
			},
			expEventIndices: []int{1},
		},
		{
			note:       "breakpoint on line with single event (2)",
			breakpoint: location.Location{File: "test.rego", Row: 2},
			events: []*topdown.Event{
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
			},
			expEventIndices: []int{2},
		},
		{
			note:       "breakpoint on line with multiple consecutive events",
			breakpoint: location.Location{File: "test.rego", Row: 2},
			events: []*topdown.Event{
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
					Op: topdown.UnifyOp,
					Location: &location.Location{
						File: "test.rego",
						Row:  2,
					},
				},
				{ // 4
					Op: topdown.EvalOp,
					Location: &location.Location{
						File: "test.rego",
						Row:  3,
					},
				},
			},
			expEventIndices: []int{2, 3},
		},
		{
			note:       "breakpoint on reoccurring line",
			breakpoint: location.Location{File: "test.rego", Row: 2},
			events: []*topdown.Event{
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
					Op: topdown.EvalOp,
					Location: &location.Location{
						File: "test.rego",
						Row:  3,
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
					Op: topdown.RedoOp,
					Location: &location.Location{
						File: "test.rego",
						Row:  1,
					},
				},
			},
			expEventIndices: []int{2, 4},
		},
	}

	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			stk := newTestStack(tc.events...)
			eh := newTestEventHandler()
			l := logging.New()
			l.SetLevel(logging.Debug)
			d, s := setupDebuggerSession(ctx, stk, LaunchProperties{}, eh.HandleEvent, l)

			bps, err := d.SetBreakpoints([]location.Location{tc.breakpoint})
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(bps) != 1 {
				t.Fatalf("Expected 1 breakpoint, got %d", len(bps))
			}

			bp := bps[0]
			if bp.Location().File != tc.breakpoint.File {
				t.Errorf("Expected breakpoint file %s, got %s", tc.breakpoint.File, bps[0].Location().File)
			}

			if bp.Location().Row != tc.breakpoint.Row {
				t.Errorf("Expected breakpoint row %d, got %d", tc.breakpoint.Row, bps[0].Location().Row)
			}

			s.start(ctx)

			var stoppedAt []int
			test.EventuallyOrFatal(t, 5*time.Second, func() bool {
				for {
					fmt.Println("WAITING FOR EVENT")
					e := eh.NextBlocking()
					fmt.Printf("EVENT: %v\n", e)
					if e == nil || e.Type == TerminatedEventType {
						return true
					}
					if e.Type == StoppedEventType {
						stoppedAt = append(stoppedAt, e.stackIndex)
						if err := d.Resume(e.Thread); err != nil {
							t.Fatalf("Unexpected error resuming: %v", err)
						}
					}
				}
			})

			if !reflect.DeepEqual(stoppedAt, tc.expEventIndices) {
				t.Errorf("Expected to stop at event indices %v, got %v", tc.expEventIndices, stoppedAt)
			}

			fmt.Println("DONE")
		})
	}
}

func setupDebuggerSession(ctx context.Context, stk stack, launchProperties LaunchProperties, eh EventHandler, l logging.Logger) (*Debugger, *session) {
	if l == nil {
		l = logging.NewNoOpLogger()
	}

	opts := []DebuggerOption{SetLogger(l)}
	if eh != nil {
		opts = append(opts, SetEventHandler(eh))
	}

	d := NewDebugger(ctx, opts...)
	thr := newThread(1, "test", stk, d.varManager, l)
	s := newSession(d, launchProperties, []*thread{thr})

	return d, s
}

type testEventHandler struct {
	ch chan *DebugEvent
}

func newTestEventHandler() *testEventHandler {
	return &testEventHandler{
		ch: make(chan *DebugEvent),
	}
}

func (teh *testEventHandler) HandleEvent(event DebugEvent) {
	teh.ch <- &event
}

func (teh *testEventHandler) Next(duration time.Duration) *DebugEvent {
	select {
	case e := <-teh.ch:
		return e
	case <-time.After(duration):
		return nil
	}
}

func (teh *testEventHandler) NextBlocking() *DebugEvent {
	return <-teh.ch
}

func (teh *testEventHandler) WaitFor(eventType EventType) *DebugEvent {
	for {
		e := <-teh.ch
		if e.Type == eventType {
			return e
		}
	}
}

type testStack struct {
	events []*topdown.Event
	index  int
	closed bool
}

func newTestStack(events ...*topdown.Event) stack {
	return &testStack{
		events: events,
		index:  -1,
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
	if ts.index < 0 || ts.index >= len(ts.events) {
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
