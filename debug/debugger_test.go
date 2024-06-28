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
			expEventIndex: -1,
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
			note: "Stop on end of trace",
			props: LaunchProperties{
				StopOnResult: true,
			},
			expEventType:  StoppedEventType,
			expEventIndex: -1,
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
			Op:      topdown.EvalOp,
			QueryID: 0,
		},
		{ // 1
			Op:      topdown.EnterOp,
			QueryID: 1,
			Location: &location.Location{
				File: "test.rego",
				Row:  1,
			},
		},
		{ // 2
			Op:      topdown.EvalOp,
			QueryID: 1,
			Location: &location.Location{
				File: "test.rego",
				Row:  2,
			},
		},
		{ // 3
			Op:      topdown.FailOp,
			QueryID: 1,
			Location: &location.Location{
				File: "test.rego",
				Row:  2,
			},
		},
		{ // 4
			Op:      topdown.RedoOp,
			QueryID: 1,
			Location: &location.Location{
				File: "test.rego",
				Row:  2,
			},
		},
		{ // 5
			Op:      topdown.ExitOp,
			QueryID: 1,
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
			l := logging.New()
			l.SetLevel(logging.Debug)
			_, s, _ := setupDebuggerSession(ctx, stk, tc.props, eh.HandleEvent, l)
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
					Op:      topdown.EvalOp,
					QueryID: 0,
				},
				{ // 1
					Op:      topdown.EnterOp,
					QueryID: 1,
					Location: &location.Location{
						File: "test.rego",
						Row:  1,
					},
				},
				{ // 2
					Op:      topdown.EvalOp,
					QueryID: 1,
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
					Op:      topdown.EvalOp,
					QueryID: 0,
				},
				{ // 1
					Op:      topdown.EnterOp,
					QueryID: 1,
					Location: &location.Location{
						File: "test.rego",
						Row:  1,
					},
				},
				{ // 2
					Op:      topdown.EvalOp,
					QueryID: 1,
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
					Op:      topdown.EvalOp,
					QueryID: 0,
				},
				{ // 1
					Op:      topdown.EnterOp,
					QueryID: 1,
					Location: &location.Location{
						File: "test.rego",
						Row:  1,
					},
				},
				{ // 2
					Op:      topdown.EvalOp,
					QueryID: 1,
					Location: &location.Location{
						File: "test.rego",
						Row:  2,
					},
				},
				{ // 3
					Op:      topdown.UnifyOp,
					QueryID: 1,
					Location: &location.Location{
						File: "test.rego",
						Row:  2,
					},
				},
				{ // 4
					Op:      topdown.EvalOp,
					QueryID: 1,
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
			d, s, _ := setupDebuggerSession(ctx, stk, LaunchProperties{}, eh.HandleEvent, nil)

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
					e := eh.NextBlocking()
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
		})
	}
}

// TODO: Test resume

func TestDebuggerStepIn(t *testing.T) {
	tests := []struct {
		note            string
		events          []*topdown.Event
		expEventIndices []int
	}{
		{
			note: "single query",
			events: []*topdown.Event{
				{ // 0
					Op:      topdown.EvalOp,
					QueryID: 1,
				},
				{ // 1
					Op:      topdown.EvalOp,
					QueryID: 1,
				},
				{ // 2
					Op:      topdown.EvalOp,
					QueryID: 1,
				},
			},
			expEventIndices: []int{0, 1, 2},
		},
		{
			note: "multiple nested queries",
			events: []*topdown.Event{
				{ // 0
					Op:      topdown.EvalOp,
					QueryID: 0,
				},
				{ // 1
					Op:      topdown.EvalOp,
					QueryID: 1,
				},
				{ // 2
					Op:      topdown.EvalOp,
					QueryID: 2,
				},
				{ // 3
					Op:      topdown.RedoOp,
					QueryID: 2,
				},
				{ // 4
					Op:      topdown.RedoOp,
					QueryID: 1,
				},
				{ // 5
					Op:      topdown.RedoOp,
					QueryID: 0,
				},
			},
			expEventIndices: []int{0, 1, 2, 3, 4, 5},
		},
		{
			note: "multiple queries",
			events: []*topdown.Event{
				{ // 0
					Op:      topdown.EvalOp,
					QueryID: 0,
				},
				{ // 1
					Op:      topdown.EvalOp,
					QueryID: 1,
				},
				{ // 2
					Op:      topdown.EvalOp,
					QueryID: 2,
				},
				{ // 3
					Op:      topdown.RedoOp,
					QueryID: 2,
				},
				{ // 4
					Op:      topdown.RedoOp,
					QueryID: 1,
				},
				{ // 5
					Op:      topdown.RedoOp,
					QueryID: 0,
				},
				{ // 6
					Op:      topdown.EvalOp,
					QueryID: 1,
				},
				{ // 7
					Op:      topdown.EvalOp,
					QueryID: 2,
				},
			},
			expEventIndices: []int{0, 1, 2, 3, 4, 5, 6, 7},
		},
	}

	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			stk := newTestStack(tc.events...)
			eh := newTestEventHandler()
			d, _, thr := setupDebuggerSession(ctx, stk, LaunchProperties{}, eh.HandleEvent, nil)

			var stoppedAt []int
			doneCh := make(chan struct{})
			defer close(doneCh)
			go func() {
				for {
					fmt.Println("WAITING FOR EVENT")
					e := eh.NextBlocking()
					fmt.Printf("EVENT: %v\n", e)

					if e == nil || e.Type == TerminatedEventType {
						break
					}

					if e.Type == StoppedEventType {
						stoppedAt = append(stoppedAt, e.stackIndex)
					}
				}
				fmt.Println("DONE")
				doneCh <- struct{}{}
			}()

			go func() {
				for {
					if err := d.StepIn(thr.id); err != nil {
						t.Errorf("Unexpected error stepping in: %v", err)
						break
					}
				}
			}()

			select {
			//case <-time.After(5 * time.Second):
			//	t.Fatal("Timed out waiting for debugger to finish")
			case <-doneCh:
			}

			if !reflect.DeepEqual(stoppedAt, tc.expEventIndices) {
				t.Errorf("Expected to stop at event indices %v, got %v", tc.expEventIndices, stoppedAt)
			}
		})
	}
}

// TODO: Test step-over

// TODO: Test step-out

func setupDebuggerSession(ctx context.Context, stk stack, launchProperties LaunchProperties, eh EventHandler, l logging.Logger) (*Debugger, *session, *thread) {
	if l == nil {
		l = logging.NewNoOpLogger()
	}

	opts := []DebuggerOption{SetLogger(l)}
	if eh != nil {
		opts = append(opts, SetEventHandler(eh))
	}

	d := NewDebugger(ctx, opts...)
	t := newThread(1, "test", stk, d.varManager, l)
	s := newSession(d, launchProperties, []*thread{t})

	return d, s, t
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
	return true
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
		ts.index++
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
