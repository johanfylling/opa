// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import (
	"context"
	"fmt"

	"github.com/google/go-dap"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/rego"
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
	varManager      *variableManager
	logger          logging.Logger
}

func newThread(id int, name string, stack stack, varManager *variableManager, logger logging.Logger) *thread {
	return &thread{
		id:         id,
		name:       name,
		stack:      stack,
		logger:     logger,
		varManager: varManager,
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

func (t *thread) resume() {
	t.breakpointLatch.unblock()
}

func (t *thread) current() (*topdown.Event, error) {
	_, e := t.stack.Current()
	return e, nil
}

func (t *thread) stepIn() error {
	if t.stopped {
		return fmt.Errorf("thread stopped")
	}

	id, e := t.stack.Next()
	t.logger.Debug("Stepping in to event: #%d", id)

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

func (t *thread) stepOver() error {
	if t.stopped {
		return fmt.Errorf("thread stopped")
	}

	c, err := t.current()
	if err != nil {
		return err
	}

	for {
		id, e := t.stack.Next()
		if c == nil || e != nil && e.QueryID <= c.QueryID {
			t.logger.Debug("Stepping over to event: #%d", id)
		} else {
			t.logger.Debug("Stepping over event: #%d", id)
		}

		br, s, err := t.eventHandler(t, e, t.state)
		if err != nil {
			return err
		}
		t.state = s

		if br || e == nil || c != nil && e.QueryID <= c.QueryID {
			t.logger.Debug("Resuming on query: %d", e.QueryID)
			break
		} else {
			t.logger.Debug("Continuing past query: %d", e.QueryID)
		}
	}

	return nil
}

func (t *thread) stepOut() error {
	if t.stopped {
		return fmt.Errorf("thread stopped")
	}

	c, err := t.current()
	if err != nil {
		return err
	}

	for {
		id, e := t.stack.Next()
		if c == nil || e != nil && e.QueryID < c.QueryID {
			t.logger.Debug("Stepping out to event: #%d", id)
		} else {
			t.logger.Debug("Stepping out event: #%d", id)
		}

		br, s, err := t.eventHandler(t, e, t.state)
		if err != nil {
			return err
		}
		t.state = s

		if br || e == nil || e.QueryID < c.QueryID {
			t.logger.Debug("Resuming on query: %d", e.QueryID)
			break
		} else {
			t.logger.Debug("Continuing past query: %d", e.QueryID)
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

func (t *thread) scopes(stackIndex int) []dap.Scope {
	e := t.stack.Event(stackIndex)
	if e == nil {
		return nil
	}

	scopes := make([]dap.Scope, 0, 3)

	// TODO: Clients are expected to keep track of fetched scopes and variable references (vs-code does),
	// but it wouldn't hurt to not register the same var-getter callback more than once.
	localScope := dap.Scope{
		Name:               "Locals",
		NamedVariables:     e.Locals.Len(),
		VariablesReference: t.localVars(e),
		Source: &dap.Source{
			Name: e.Location.File,
			Path: e.Location.File,
		},
		Line:    e.Location.Row,
		EndLine: e.Location.Row,
	}
	scopes = append(scopes, localScope)

	if e.Input() != nil {
		inputScope := dap.Scope{
			Name:               "Input",
			NamedVariables:     1,
			VariablesReference: t.inputVars(e),
		}
		scopes = append(scopes, inputScope)
	}

	if rs := t.stack.Result(); rs != nil {
		resultScope := dap.Scope{
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

func (t *thread) stop() {
	t.stopped = true
}

func (t *thread) done() bool {
	return t.stopped || !t.stack.Enabled()
}
