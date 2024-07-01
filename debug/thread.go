// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/ast/location"
	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
)

type threadState interface{}

type eventAction string

const (
	nopAction   eventAction = "nop"
	breakAction eventAction = "break"
	skipAction  eventAction = "skip"
	stopAction  eventAction = "stop"
)

type eventHandler func(t *thread, stackIndex int, e *topdown.Event, s threadState) (eventAction, threadState, error)

type Thread interface {
	Id() int
	Name() string
}

type thread struct {
	id              int
	name            string
	stack           stack
	eventHandler    eventHandler
	breakpointLatch latch
	stopped         bool
	state           threadState
	varManager      *variableManager
	logger          logging.Logger
}

func (t *thread) Id() int {
	return t.id
}

func (t *thread) Name() string {
	return t.name
}

func newThread(id int, name string, stack stack, varManager *variableManager, logger logging.Logger) *thread {
	t := &thread{
		id:         id,
		name:       name,
		stack:      stack,
		logger:     logger,
		varManager: varManager,
	}

	// Threads are always created in a paused state.
	_ = t.pause()

	return t
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

		t.logger.Debug("Waiting on breakpoint latch")
		t.breakpointLatch.wait()
		t.logger.Debug("Breakpoint latch released")

		// The thread could get resumed by another goroutine before the eventHandler returns, so we preemptively lock the
		// breakpoint latch and unlock it of we're not supposed to break.
		t.logger.Debug("Preemptively blocking breakpoint latch")
		t.breakpointLatch.block()

		a, err := t.stepIn()
		if err != nil {
			t.stopped = true
			return err
		}

		if a == breakAction {
			t.logger.Debug("break requested; not unblocking breakpoint latch")
		} else {
			t.logger.Debug("No break requested; unblocking breakpoint latch")
			t.breakpointLatch.unblock()
		}
	}
}

func (t *thread) pause() error {
	t.logger.Debug("Pausing thread: %d", t.id)
	t.breakpointLatch.block()
	return nil
}

func (t *thread) resume() error {
	t.logger.Debug("Resuming thread: %d", t.id)
	t.breakpointLatch.unblock()
	return nil
}

func (t *thread) current() (int, *topdown.Event, error) {
	i, e := t.stack.Current()
	return i, e, nil
}

func (t *thread) stepIn() (eventAction, error) {
	if t.stopped {
		return nopAction, fmt.Errorf("thread stopped")
	}

	i, e := t.stack.Next()
	t.logger.Debug("Step-in on event: #%d", i)

	a, s, err := t.eventHandler(t, i, e, t.state)
	if err != nil {
		return nopAction, err
	}
	t.state = s

	return a, nil
}

func (t *thread) stepOver() error {
	if t.stopped {
		return fmt.Errorf("thread stopped")
	}

	_, startE, err := t.current()
	if err != nil {
		return err
	}

	baseQueryVisited := false
Loop:
	for {
		i, e := t.stack.Next()
		t.logger.Debug("Step-over on event: #%d", i)

		if e != nil && e.QueryID == 0 {
			baseQueryVisited = true
		}

		a, s, err := t.eventHandler(t, i, e, t.state)
		if err != nil {
			return err
		}
		t.state = s

		if a == skipAction {
			continue
		}

		var qid uint64 = 0
		if e != nil {
			qid = e.QueryID
		}

		switch {
		case startE == nil:
			t.logger.Debug("Resuming on query: %d; first event", qid)
			break Loop
		case a == breakAction:
			t.logger.Debug("Resuming on query: %d; break-action", qid)
			break Loop
		case e == nil:
			t.logger.Debug("Resuming on query: %d; no event", qid)
			break Loop
		case e.QueryID == 0:
			t.logger.Debug("Continuing past query: %d; base-query", qid)
		case e.QueryID <= startE.QueryID:
			t.logger.Debug("Resuming on query: %d; start-query: %d", qid, startE.QueryID)
			break Loop
		case baseQueryVisited:
			t.logger.Debug("Resuming on query: %d; base-query visited", qid)
			break Loop
		default:
			t.logger.Debug("Continuing past query: %d", qid)
		}
	}

	return nil
}

func (t *thread) stepOut() error {
	if t.stopped {
		return fmt.Errorf("thread stopped")
	}

	_, c, err := t.current()
	if err != nil {
		return err
	}

	for {
		i, e := t.stack.Next()
		t.logger.Debug("Step-out on event: #%d", i)

		a, s, err := t.eventHandler(t, i, e, t.state)
		if err != nil {
			return err
		}
		t.state = s

		if a == skipAction {
			continue
		}

		var qid uint64 = 0
		if e != nil {
			qid = e.QueryID
		}

		if a == breakAction || e == nil || c == nil || qid < c.QueryID {
			t.logger.Debug("Resuming on query: %d", qid)
			break
		} else {
			t.logger.Debug("Continuing past query: %d", qid)
		}
	}

	return nil
}

func (t *thread) stackEvents(from int) []*topdown.Event {
	var events []*topdown.Event
	for {
		e := t.stack.Event(from)
		if e == nil {
			break
		}
		events = append(events, e)
		from++
	}
	return events
}

type Scope struct {
	Name               string
	NamedVariables     int
	VariablesReference int
	Location           *location.Location
}

func (t *thread) scopes(stackIndex int) []Scope {
	e := t.stack.Event(stackIndex)
	if e == nil {
		return nil
	}

	scopes := make([]Scope, 0, 3)

	// TODO: Clients are expected to keep track of fetched scopes and variable references (vs-code does),
	// but it wouldn't hurt to not register the same var-getter callback more than once.
	if e.Locals.Len() > 0 {
		localScope := Scope{
			Name:               "Locals",
			NamedVariables:     e.Locals.Len(),
			VariablesReference: t.localVars(e),
			Location:           e.Location,
		}
		scopes = append(scopes, localScope)
	}

	if e.Input() != nil {
		inputScope := Scope{
			Name:               "Input",
			NamedVariables:     1,
			VariablesReference: t.inputVars(e),
		}
		scopes = append(scopes, inputScope)
	}

	if rs := t.stack.Result(); rs != nil {
		resultScope := Scope{
			Name:               "Result Set",
			NamedVariables:     1,
			VariablesReference: t.resultVars(rs),
		}
		scopes = append(scopes, resultScope)
	}

	return scopes
}

func (t *thread) localVars(e *topdown.Event) int {
	return t.varManager.addVars(func() []namedVar {
		if e == nil {
			return nil
		}

		vars := make([]namedVar, 0, e.Locals.Len())

		e.Locals.Iter(func(k, v ast.Value) bool {
			name := k.(ast.Var)
			variable := namedVar{
				Name:  string(name),
				Value: v,
			}

			meta, ok := e.LocalMetadata[name]
			if ok {
				variable.Name = string(meta.Name)
			}

			vars = append(vars, variable)
			return false
		})

		return vars
	})
}

func (t *thread) inputVars(e *topdown.Event) int {
	return t.varManager.addVars(func() []namedVar {
		input := e.Input()
		if input == nil {
			return nil
		}

		return []namedVar{{Name: "input", Value: input.Value}}
	})
}

func (t *thread) resultVars(rs rego.ResultSet) int {
	vars := make([]namedVar, 0, len(rs))
	for i, result := range rs {
		bindings, err := ast.InterfaceToValue(result.Bindings)
		if err != nil {
			continue
		}

		expressions := &ast.Array{}
		for _, expr := range result.Expressions {
			t := ast.StringTerm(expr.Text)
			v, err := ast.InterfaceToValue(expr.Value)
			if err != nil {
				continue
			}
			expressions = expressions.Append(ast.NewTerm(ast.NewObject(
				ast.Item(ast.StringTerm("text"), t),
				ast.Item(ast.StringTerm("value"), ast.NewTerm(v)),
			)))
		}

		res := ast.NewObject(
			ast.Item(ast.StringTerm("bindings"), ast.NewTerm(bindings)),
			ast.Item(ast.StringTerm("expressions"), ast.NewTerm(expressions)),
		)

		vars = append(vars, namedVar{
			Name:  fmt.Sprintf("%d", i),
			Value: res,
		})
	}

	return t.varManager.addVars(func() []namedVar {
		return vars
	})
}

func (t *thread) close() error {
	t.stopped = true
	t.breakpointLatch.Close()
	return t.stack.Close()
}

func (t *thread) done() bool {
	return t.stopped || !t.stack.Enabled()
}
