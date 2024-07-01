// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/ast/location"
	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/util/test"
)

func TestDebuggerLaunchEval(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(10*time.Second))
	defer cancel()

	files := map[string]string{
		"test1.rego": `package test
import rego.v1
import data.util

p if {
	print("hello")
	x := util.f(1, 2)
	y := util.f(3, 4)
	x < y
	data.foo != input.foo
	print("bye")
}
`,
		"test2.rego": `package util
import rego.v1

f(a, b) := c if {
	x := a + b
	c := x * 2
}
`,
		"data.json": `{"foo": "bar"}`,
	}

	input := `{"foo": "baz"}`

	test.WithTempFS(files, func(rootDir string) {
		eh := newTestEventHandler()
		d := NewDebugger(ctx, SetEventHandler(eh.HandleEvent))

		launchProps := LaunchProperties{
			BundlePaths: []string{rootDir},
			Input:       input,
			Query:       "x = data.test.p",
		}

		err := d.LaunchEval(launchProps)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if _, err := d.SetBreakpoints([]location.Location{{File: "test1.rego", Row: 7}}); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		threads, err := d.Threads()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(threads) != 1 {
			t.Fatalf("Expected 1 thread, got %d", len(threads))
		}

		if err := d.ResumeAll(); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		eh.WaitFor(ctx, StoppedEventType)

		t.Fatal("TODO")
	})
}

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
			d, s, _ := setupDebuggerSession(ctx, stk, tc.props, eh.HandleEvent, l)
			s.start(ctx)
			if err := d.ResumeAll(); err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

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
			if err := d.ResumeAll(); err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

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
			note: "nested queries",
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
			note: "sequential queries",
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
			case <-time.After(5 * time.Second):
				t.Fatal("Timed out waiting for debugger to finish")
			case <-doneCh:
			}

			if !reflect.DeepEqual(stoppedAt, tc.expEventIndices) {
				t.Errorf("Expected to stop at event indices %v, got %v", tc.expEventIndices, stoppedAt)
			}
		})
	}
}

func TestDebuggerStepOver(t *testing.T) {
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
			note: "nested queries",
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
					QueryID: 1,
				},
			},
			expEventIndices: []int{0, 1, 4, 5},
		},
		{
			note: "multiple nested queries",
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
					QueryID: 2,
				},
				{ // 3
					Op:      topdown.EvalOp,
					QueryID: 3,
				},
				{ // 4
					Op:      topdown.RedoOp,
					QueryID: 3,
				},
				{ // 5
					Op:      topdown.RedoOp,
					QueryID: 2,
				},
				{ // 6
					Op:      topdown.RedoOp,
					QueryID: 1,
				},
				{ // 7
					Op:      topdown.RedoOp,
					QueryID: 1,
				},
			},
			expEventIndices: []int{0, 1, 6, 7},
		},
		{
			note: "sequential queries",
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
					Op:      topdown.EvalOp,
					QueryID: 2,
				},
				{ // 6
					Op:      topdown.EvalOp,
					QueryID: 1,
				},
			},
			expEventIndices: []int{0, 1, 4, 6},
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
					e := eh.NextBlocking()

					if e == nil || e.Type == TerminatedEventType {
						break
					}

					if e.Type == StoppedEventType {
						stoppedAt = append(stoppedAt, e.stackIndex)
					}
				}
				doneCh <- struct{}{}
			}()

			go func() {
				for {
					if err := d.StepOver(thr.id); err != nil {
						t.Errorf("Unexpected error stepping over: %v", err)
						break
					}
				}
			}()

			select {
			case <-time.After(5 * time.Second):
				t.Fatal("Timed out waiting for debugger to finish")
			case <-doneCh:
			}

			if !reflect.DeepEqual(stoppedAt, tc.expEventIndices) {
				t.Errorf("Expected to stop at event indices %v, got %v", tc.expEventIndices, stoppedAt)
			}
		})
	}
}

func TestDebuggerStepOut(t *testing.T) {
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
			// We always expect to stop on the first stack event
			expEventIndices: []int{0},
		},
		{
			note: "single query to step out of",
			events: []*topdown.Event{
				{ // 0
					Op:      topdown.EvalOp,
					QueryID: 2,
				},
				{ // 1
					Op:      topdown.EvalOp,
					QueryID: 2,
				},
				{ // 2
					Op:      topdown.EvalOp,
					QueryID: 1,
				},
				{ // 3
					Op:      topdown.RedoOp,
					QueryID: 1,
				},
			},

			expEventIndices: []int{0, 2},
		},
		{
			note: "multiple queries to step out of",
			events: []*topdown.Event{
				{ // 0
					Op:      topdown.EvalOp,
					QueryID: 3,
				},
				{ // 1
					Op:      topdown.EvalOp,
					QueryID: 3,
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
					Op:      topdown.EvalOp,
					QueryID: 1,
				},
			},

			expEventIndices: []int{0, 2, 4},
		},
		{
			note: "step-out also steps-over",
			events: []*topdown.Event{
				{ // 0
					Op:      topdown.EvalOp,
					QueryID: 3,
				},
				// Extra query to step over
				{ // 1
					Op:      topdown.EvalOp,
					QueryID: 4,
				},
				{ // 2
					Op:      topdown.RedoOp,
					QueryID: 4,
				},
				{ // 3
					Op:      topdown.EvalOp,
					QueryID: 3,
				},
				{ // 4
					Op:      topdown.EvalOp,
					QueryID: 2,
				},
				{ // 5
					Op:      topdown.RedoOp,
					QueryID: 2,
				},
			},
			expEventIndices: []int{0, 4},
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
					if err := d.StepOut(thr.id); err != nil {
						t.Errorf("Unexpected error stepping over: %v", err)
						break
					}
				}
			}()

			select {
			case <-time.After(5 * time.Second):
				t.Fatal("Timed out waiting for debugger to finish")
			case <-doneCh:
			}

			if !reflect.DeepEqual(stoppedAt, tc.expEventIndices) {
				t.Errorf("Expected to stop at event indices %v, got %v", tc.expEventIndices, stoppedAt)
			}
		})
	}
}

func TestDebuggerStackTrace(t *testing.T) {
	tests := []struct {
		note     string
		events   []*topdown.Event
		expTrace []StackFrame
	}{
		{
			note:     "empty stack",
			expTrace: []StackFrame{},
		},
		{
			note: "single stack frame, no event node",
			events: []*topdown.Event{
				{
					Op:      topdown.EvalOp,
					QueryID: 1,
					Location: &location.Location{
						File: "test.rego",
						Row:  42,
					},
				},
			},
			expTrace: []StackFrame{
				{
					Id:   1,
					Name: "#1: 1 Eval, test.rego:42",
					Location: &location.Location{
						File: "test.rego",
						Row:  42,
					},
				},
			},
		},
		{
			note: "single stack frame, event node",
			events: []*topdown.Event{
				{
					Op:      topdown.EvalOp,
					Node:    ast.MustParseExpr("data.test.p[x]"),
					QueryID: 1,
					Location: &location.Location{
						File: "test.rego",
						Row:  42,
					},
				},
			},
			expTrace: []StackFrame{
				{
					Id:   1,
					Name: "#1: 1 | Eval data.test.p[x]",
					Location: &location.Location{
						File: "test.rego",
						Row:  42,
					},
				},
			},
		},
		{
			note: "multiple stack frames",
			events: []*topdown.Event{
				{
					Op:      topdown.EvalOp,
					Node:    ast.MustParseExpr("y := data.test.p[x]"),
					QueryID: 5,
					Location: &location.Location{
						File: "test.rego",
						Row:  2,
					},
				},
				{
					Op:      topdown.UnifyOp,
					Node:    ast.MustParseExpr("y = 1"),
					QueryID: 5,
					Location: &location.Location{
						File: "test.rego",
						Row:  3,
					},
				},
			},
			// Reversed order
			expTrace: []StackFrame{
				{
					Id:   2,
					Name: "#2: 5 | Unify y = 1",
					Location: &location.Location{
						File: "test.rego",
						Row:  3,
					},
				},
				{
					Id:   1,
					Name: "#1: 5 | Eval assign(y, data.test.p[x])",
					Location: &location.Location{
						File: "test.rego",
						Row:  2,
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
			defer cancel()

			l := logging.New()
			l.SetLevel(logging.Debug)

			stk := newTestStack(tc.events...)
			eh := newTestEventHandler()
			d, s, thr := setupDebuggerSession(ctx, stk, LaunchProperties{}, eh.HandleEvent, l)

			s.start(ctx)
			if err := d.ResumeAll(); err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if e := eh.WaitFor(ctx, TerminatedEventType); e == nil {
				t.Fatal("Run never terminated")
			}

			trace, err := d.StackTrace(thr.id)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(trace) != len(tc.expTrace) {
				t.Fatalf("Expected %d stack frames, got %d", len(tc.expTrace), len(trace))
			}

			if !reflect.DeepEqual(trace, tc.expTrace) {
				t.Errorf("Expected stack trace:\n\n%v\n\ngot:\n\n%v", tc.expTrace, trace)
			}
		})
	}
}

func TestDebuggerScopeVariables(t *testing.T) {
	tests := []struct {
		note      string
		input     *ast.Term
		locals    map[ast.Var]ast.Value
		result    *rego.ResultSet
		expScopes map[string]scopeInfo
	}{
		{
			note: "no variables",
		},
		{
			note: "input (object)",
			input: ast.ObjectTerm(
				ast.Item(ast.StringTerm("x"), ast.NumberTerm("1")),
				ast.Item(ast.StringTerm("y"), ast.BooleanTerm(true))),
			expScopes: map[string]scopeInfo{
				"Input": {
					name:           "Input",
					namedVariables: 1,
					variables: map[string]varInfo{
						"input": {
							typ: "object",
							val: `{"x": 1, "y": true}`,
							children: map[string]varInfo{
								`"x"`: {
									typ: "number",
									val: "1",
								},
								`"y"`: {
									typ: "bool",
									val: "true",
								},
							},
						},
					},
				},
			},
		},
		{
			note: "input (array)",
			input: ast.ArrayTerm(
				ast.StringTerm("foo"),
				ast.NumberTerm("1"),
				ast.BooleanTerm(true)),
			expScopes: map[string]scopeInfo{
				"Input": {
					name:           "Input",
					namedVariables: 1,
					variables: map[string]varInfo{
						"input": {
							typ: "array",
							val: `["foo", 1, true]`,
							children: map[string]varInfo{
								"0": {
									typ: "string",
									val: `"foo"`,
								},
								"1": {
									typ: "number",
									val: "1",
								},
								"2": {
									typ: "bool",
									val: "true",
								},
							},
						},
					},
				},
			},
		},
		{
			note: "local vars",
			locals: map[ast.Var]ast.Value{
				ast.Var("x"): ast.Number("42"),
				ast.Var("y"): ast.Boolean(true),
				ast.Var("z"): ast.String("foo"),
				ast.Var("obj"): ast.NewObject(
					ast.Item(ast.StringTerm("a"), ast.NumberTerm("1")),
					ast.Item(ast.StringTerm("b"), ast.NumberTerm("2"))),
				ast.Var("arr"): ast.NewArray(ast.NumberTerm("1"), ast.NumberTerm("2"), ast.NumberTerm("3")),
			},
			expScopes: map[string]scopeInfo{
				"Locals": {
					name:           "Locals",
					namedVariables: 5,
					variables: map[string]varInfo{
						"x": {
							typ: "number",
							val: "42",
						},
						"y": {
							typ: "bool",
							val: "true",
						},
						"z": {
							typ: "string",
							val: `"foo"`,
						},
						"obj": {
							typ: "object",
							val: `{"a": 1, "b": 2}`,
							children: map[string]varInfo{
								`"a"`: {
									typ: "number",
									val: "1",
								},
								`"b"`: {
									typ: "number",
									val: "2",
								},
							},
						},
						"arr": {
							typ: "array",
							val: "[1, 2, 3]",
							children: map[string]varInfo{
								"0": {
									typ: "number",
									val: "1",
								},
								"1": {
									typ: "number",
									val: "2",
								},
								"2": {
									typ: "number",
									val: "3",
								},
							},
						},
					},
				},
			},
		},
		{
			note: "local var with long text description",
			locals: map[ast.Var]ast.Value{
				ast.Var("x"): ast.String(strings.Repeat("x", 1000)),
			},
			expScopes: map[string]scopeInfo{
				"Locals": {
					name:           "Locals",
					namedVariables: 1,
					variables: map[string]varInfo{
						"x": {
							typ: "string",
							val: fmt.Sprintf(`"%s...`, strings.Repeat("x", 97)),
						},
					},
				},
			},
		},
		{
			note: "result",
			result: &rego.ResultSet{
				rego.Result{
					Expressions: []*rego.ExpressionValue{
						{
							Value: ast.Boolean(true),
							Text:  "x = data.test.allow",
						},
					},
					Bindings: map[string]interface{}{
						"x": ast.Boolean(true),
					},
				},
			},
			expScopes: map[string]scopeInfo{
				"Result Set": {
					name:           "Result Set",
					namedVariables: 1,
					variables: map[string]varInfo{
						"0": {
							typ: "object",
							val: `{"bindings": {"x": true}, "expressions": [{"text": "x = data.test.allow", "value": true}]}`,
							children: map[string]varInfo{
								`"bindings"`: {
									typ: "object",
									val: `{"x": true}`,
									children: map[string]varInfo{
										`"x"`: {
											typ: "bool",
											val: "true",
										},
									},
								},
								`"expressions"`: {
									typ: "array",
									val: `[{"text": "x = data.test.allow", "value": true}]`,
									children: map[string]varInfo{
										"0": {
											typ: "object",
											val: `{"text": "x = data.test.allow", "value": true}`,
											children: map[string]varInfo{
												`"text"`: {
													typ: "string",
													val: `"x = data.test.allow"`,
												},
												`"value"`: {
													typ: "bool",
													val: "true",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			locals := ast.NewValueMap()
			for k, v := range tc.locals {
				locals.Put(k, v)
			}

			e := topdown.Event{
				Op:     topdown.EvalOp,
				Locals: locals,
			}

			e.WithInput(tc.input)
			events := []*topdown.Event{&e}

			stk := newTestStack(events...)

			if tc.result != nil {
				stk.result = *tc.result
			}

			stk.Next() // Move forward to the first event
			eh := newTestEventHandler()
			d, _, thr := setupDebuggerSession(ctx, stk, LaunchProperties{}, eh.HandleEvent, nil)

			trace, err := d.StackTrace(thr.id)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if len(trace) != 1 {
				t.Fatalf("Expected 1 stack frame, got %d", len(trace))
			}

			scopes, err := d.Scopes(trace[0].Id)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(scopes) != len(tc.expScopes) {
				t.Fatalf("Expected %d scopes, got %d", len(tc.expScopes), len(scopes))
			}

			for i, scope := range scopes {
				expScope, ok := tc.expScopes[scope.Name]
				if !ok {
					t.Errorf("Unexpected scope: %s", scopes[i].Name)
					continue
				}

				if scope.Name != expScope.name {
					t.Errorf("Expected scope name %s, got %s", expScope.name, scope.Name)
				}
				if scope.NamedVariables != expScope.namedVariables {
					t.Errorf("Expected %d named variables, got %d", expScope.namedVariables, scope.NamedVariables)
				}
				if scope.VariablesReference == 0 {
					t.Errorf("Expected non-zero variables reference")
				}

				vars, err := d.Variables(scope.VariablesReference)
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}

				if len(vars) != expScope.namedVariables {
					t.Fatalf("Expected nuber of variables to equal named variables for scope (%d), got %d", expScope.namedVariables, len(vars))
				}

				assertVariables(t, d, vars, expScope.variables)
			}
		})
	}
}

type varInfo struct {
	typ      string
	val      string
	children map[string]varInfo
}

type scopeInfo struct {
	name           string
	namedVariables int
	variables      map[string]varInfo
}

func assertVariables(t *testing.T, d *Debugger, variables []Variable, exp map[string]varInfo) {
	for _, v := range variables {
		expVar, ok := exp[v.Name]
		if !ok {
			t.Errorf("Unexpected variable: %s", v.Name)
			continue
		}

		if v.Type != expVar.typ {
			t.Errorf("Expected variable type %s, got %s", expVar.typ, v.Type)
		}

		if v.Value != expVar.val {
			t.Errorf("Expected variable value %s, got %s", expVar.val, v.Value)
		}

		if len(expVar.children) != 0 {
			if v.VariablesReference == 0 {
				t.Errorf("Expected non-zero variables reference")
			}

			vars, err := d.Variables(v.VariablesReference)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			assertVariables(t, d, vars, expVar.children)
		} else {
			if v.VariablesReference != 0 {
				t.Errorf("Expected zero variables reference")
			}
		}
	}
}

func setupDebuggerSession(ctx context.Context, stk stack, launchProperties LaunchProperties, eh EventHandler, l logging.Logger) (*Debugger, *session, *thread) {
	if l == nil {
		l = logging.NewNoOpLogger()
	}

	opts := []DebuggerOption{SetLogger(l)}
	if eh != nil {
		opts = append(opts, SetEventHandler(eh))
	}

	varManager := newVariableManager()
	d := NewDebugger(ctx, opts...)
	t := newThread(1, "test", stk, varManager, l)
	s := newSession(d, varManager, launchProperties, []*thread{t})

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

func (teh *testEventHandler) WaitFor(ctx context.Context, eventType EventType) *DebugEvent {
	for {
		select {
		case e := <-teh.ch:
			if e.Type == eventType {
				return e
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (teh *testEventHandler) IgnoreAll(ctx context.Context) {
	go func() {
		for {
			select {
			case <-teh.ch:
			case <-ctx.Done():
				return
			}
		}
	}()
}

type testStack struct {
	events []*topdown.Event
	index  int
	result rego.ResultSet
	closed bool
}

func newTestStack(events ...*topdown.Event) *testStack {
	return &testStack{
		events: events,
		index:  -1,
	}
}

func (ts *testStack) done() bool {
	return ts.index >= len(ts.events)
}

func (ts *testStack) onLastEvent() bool {
	return ts.index == len(ts.events)-1
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
	if i >= 0 && i < len(ts.events) {
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
	return ts.result
}

func (ts *testStack) Close() error {
	ts.closed = true
	return nil
}
