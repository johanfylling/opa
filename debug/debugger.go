// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/open-policy-agent/opa/ast/location"
	fileurl "github.com/open-policy-agent/opa/internal/file/url"
	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
	prnt "github.com/open-policy-agent/opa/topdown/print"
)

type Debugger struct {
	ctx          context.Context
	session      *session
	logger       logging.Logger
	printHook    *printHook
	varManager   *variableManager
	eventHandler EventHandler
}

type printHook struct {
	prnt.Hook
	d *Debugger
}

func (h *printHook) Print(_ prnt.Context, str string) error {
	if h == nil || h.d == nil {
		return nil
	}
	h.d.eventHandler(StdoutEventType, 0, str)
	return nil
}

type DebuggerOption func(*Debugger)

func NewDebugger(ctx context.Context, options ...DebuggerOption) *Debugger {
	d := &Debugger{
		ctx:          ctx,
		varManager:   newVariableManager(),
		eventHandler: newNopEventHandler(),
	}
	d.printHook = &printHook{d: d}

	for _, option := range options {
		option(d)
	}

	return d
}

func SetLogger(logger logging.Logger) DebuggerOption {
	return func(d *Debugger) {
		d.logger = logger
	}
}

func SetEventHandler(handler EventHandler) DebuggerOption {
	return func(d *Debugger) {
		d.eventHandler = handler
	}
}

type LaunchProperties struct {
	BundlePaths  []string     `json:"bundles"`
	Command      string       `json:"command"`
	DataPaths    []string     `json:"data"`
	InputPath    string       `json:"input"`
	LogLevel     string       `json:"log_level"`
	Query        string       `json:"query"`
	StopOnResult bool         `json:"stop_on_result"`
	StopOnEntry  bool         `json:"stop_on_entry"`
	StopOnFail   bool         `json:"stop_on_fail"`
	EnablePrint  bool         `json:"enable_print"`
	SkipOps      []topdown.Op `json:"skip_ops"`
}

func (lp LaunchProperties) String() string {
	b, err := json.Marshal(lp)
	if err != nil {
		return fmt.Sprintf("{}")
	}
	return string(b)
}

func (d *Debugger) LaunchEval(props LaunchProperties) error {
	if d.session != nil {
		return fmt.Errorf("debug session already active")
	}

	regoArgs := []func(*rego.Rego){
		rego.Query(props.Query),
	}

	if props.EnablePrint {
		regoArgs = append(regoArgs, rego.EnablePrintStatements(true),
			rego.PrintHook(d.printHook))
	}

	if len(props.DataPaths) > 0 {
		regoArgs = append(regoArgs, rego.Load(props.DataPaths, nil))
	}

	for _, bundlePath := range props.BundlePaths {
		regoArgs = append(regoArgs, rego.LoadBundle(bundlePath))
	}

	if props.InputPath != "" {
		input, err := readInput(props.InputPath)
		if err != nil {
			return fmt.Errorf("failed to read input: %v", err)
		}
		regoArgs = append(regoArgs, rego.Input(input))
	}

	r := rego.New(regoArgs...)

	pq, err := r.PrepareForEval(d.ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare query for evaluation: %v", err)
	}

	tracer := newDebugTracer()

	evalArgs := []rego.EvalOption{
		rego.EvalRuleIndexing(true),
		rego.EvalEarlyExit(true),
		rego.EvalQueryTracer(tracer),
	}

	// Threads are 1-indexed.
	t := newThread(1, "main", tracer, d.varManager, d.logger)
	newSession(d, props, []*thread{t})

	go func() {
		defer func() { _ = tracer.Close() }()
		rs, evalErr := pq.Eval(d.session.ctx, evalArgs...)
		if evalErr != nil {
			var topdownErr *topdown.Error
			if errors.As(evalErr, &topdownErr) && topdownErr.Code == topdown.CancelErr {
				return
			}
			d.logger.Error("Evaluation failed: %v", evalErr)
			return
		}

		tracer.resultSet = rs
		d.session.result(t, rs)
	}()

	d.session.start(d.ctx)
	return nil
}

func readInput(path string) (interface{}, error) {
	path, err := fileurl.Clean(path)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var input interface{}
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, err
	}

	return input, nil
}

type session struct {
	d              *Debugger
	properties     LaunchProperties
	threads        []*thread
	frames         []*frameInfo
	framesByThread map[int][]*frameInfo
	breakpoints    *breakpointCollection
	ctx            context.Context
	cancel         context.CancelFunc
}

func newSession(debugger *Debugger, props LaunchProperties, threads []*thread) *session {
	ctx, cancel := context.WithCancel(debugger.ctx)
	s := &session{
		d:              debugger,
		properties:     props,
		threads:        threads,
		frames:         []*frameInfo{},
		framesByThread: map[int][]*frameInfo{},
		breakpoints:    newBreakpointCollection(),
		ctx:            ctx,
		cancel:         cancel,
	}
	debugger.session = s

	for _, t := range threads {
		t.eventHandler = s.handleEvent
	}

	return s
}

func (s *session) start(ctx context.Context) {
	for _, t := range s.threads {
		t := t
		go func() {
			s.d.eventHandler(ThreadEventType, t.id, "started")
			if err := t.run(ctx); err != nil {
				s.d.logger.Error("Thread %d failed: %v", t.id, err)
			}
			s.d.eventHandler(ThreadEventType, t.id, "exited")

			allStopped := true
			for _, t := range s.threads {
				if !t.done() {
					allStopped = false
					break
				}
			}

			if allStopped {
				s.d.eventHandler(TerminatedEventType, 0, "")
			}
		}()
	}
}

func (s *session) thread(id int) (*thread, error) {
	if s == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	index := id - 1
	if index < 0 || index >= len(s.threads) {
		return nil, fmt.Errorf("invalid thread id: %d", id)
	}
	return s.threads[index], nil
}

func (d *Debugger) Resume(threadId int) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("no active debug session")
	}

	t, err := d.session.thread(threadId)
	if err != nil {
		return err
	}
	return t.resume()
}

func (d *Debugger) Next(threadId int) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("no active debug session")
	}

	t, err := d.session.thread(threadId)
	if err != nil {
		return err
	}

	err = t.stepOver()
	if err == nil {
		d.eventHandler(StoppedEventType, t.id, "entry")
	}
	if t.done() {
		d.eventHandler(ThreadEventType, t.id, "exited")
		allStopped := true
		for _, t := range d.session.threads {
			if !t.done() {
				allStopped = false
				break
			}
		}
		if allStopped {
			d.eventHandler(TerminatedEventType, 0, "")
		}
	}

	return err
}

func (d *Debugger) StepIn(threadId int) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("no active debug session")
	}

	t, err := d.session.thread(threadId)
	if err != nil {
		return err
	}

	err = t.stepIn()
	if err == nil {
		d.eventHandler(StoppedEventType, t.id, "entry")
	}
	if t.done() {
		d.eventHandler(ThreadEventType, t.id, "exited")
		allStopped := true
		for _, t := range d.session.threads {
			if !t.done() {
				allStopped = false
				break
			}
		}
		if allStopped {
			d.eventHandler(TerminatedEventType, 0, "")
		}
	}

	return err
}

func (d *Debugger) StepOut(threadId int) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("no active debug session")
	}

	t, err := d.session.thread(threadId)
	if err != nil {
		return err
	}

	err = t.stepOut()
	if err == nil {
		d.eventHandler(StoppedEventType, t.id, "entry")
	}
	if t.done() {
		d.eventHandler(ThreadEventType, t.id, "exited")
		allStopped := true
		for _, t := range d.session.threads {
			if !t.done() {
				allStopped = false
				break
			}
		}
		if allStopped {
			d.eventHandler(TerminatedEventType, 0, "")
		}
	}

	return err
}

func (d *Debugger) Threads() ([]Thread, error) {
	if d == nil || d.session == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	threads := make([]Thread, 0, len(d.session.threads))
	for _, t := range d.session.threads {
		threads = append(threads, t)
	}

	return threads, nil
}

type sessionThreadState struct {
	threadState
	entered     bool
	ended       bool
	prevQueryId uint64
}

func (s *sessionThreadState) String() string {
	return fmt.Sprintf("{entered: %v, ended: %v, prevQueryId: %d}", s.entered, s.ended, s.prevQueryId)
}

func (s *session) handleEvent(t *thread, e *topdown.Event, ts threadState) (eventAction, threadState, error) {
	state, ok := ts.(*sessionThreadState)
	if state != nil && !ok {
		s.d.logger.Warn("invalid thread state: %v", s)
	}
	if state == nil {
		state = &sessionThreadState{}
	}

	defer func() {
		if e != nil {
			state.prevQueryId = e.QueryID
		} else {
			state.prevQueryId = 0
		}
	}()

	if e == nil {
		handleEnd := func() (eventAction, threadState, error) {
			t.stop()
			return stopAction, state, nil
		}

		if state.ended {
			s.d.logger.Debug("End of trace already handled")
			return handleEnd()
		}

		s.d.logger.Debug("Handling end of trace")

		state.ended = true
		if s.properties.StopOnResult {
			s.d.logger.Info("Thread %d stopped at end of trace", t.id)
			s.d.eventHandler(StoppedEventType, t.id, "result")
			return breakAction, state, nil
		}

		return handleEnd()
	}

	s.d.logger.Debug("Handling event:\n%v\n\nstate:\n%s", e, state)

	if s.skipOp(e.Op) && (state.prevQueryId == 0 || e.Op == topdown.RedoOp || e.QueryID == state.prevQueryId) {
		// We only skip an event as long as we're within the same query scope.
		s.d.logger.Debug("Skipping event (op: %v)", e.Op)
		return skipAction, state, nil
	}

	if s.properties.StopOnEntry && !state.entered && e.Location.File != "" {
		state.entered = true
		s.d.logger.Info("Thread %d stopped at entry", t.id)
		s.d.eventHandler(StoppedEventType, t.id, "entry")
		return breakAction, state, nil
	}

	if s.properties.StopOnFail && e.Op == topdown.FailOp {
		s.d.logger.Info("Thread %d stopped on failure", t.id)
		s.d.eventHandler(ExceptionEventType, t.id, string(e.Op))
		return breakAction, state, nil
	}

	if e.Location != nil && e.Location.File != "" {
		for _, bp := range s.breakpoints.allForFilePath(e.Location.File) {
			if bp.location.Row == e.Location.Row {
				s.d.logger.Info("Thread %d stopped at breakpoint: %s:%d", t.id, e.Location.File, e.Location.Row)
				s.d.eventHandler(StoppedEventType, t.id, "breakpoint")
				return breakAction, state, nil
			}
		}
	}

	return nopAction, state, nil
}

func (s *session) skipOp(op topdown.Op) bool {
	for _, skip := range s.properties.SkipOps {
		if skip == op {
			return true
		}
	}
	return false
}

func (s *session) result(t *thread, rs rego.ResultSet) {
	if rsJson, err := json.MarshalIndent(rs, "", "  "); err == nil {
		s.d.logger.Debug("Result: %s\n", rsJson)
		s.d.eventHandler(StdoutEventType, t.id, string(rsJson))
	} else {
		s.d.logger.Debug("Result: %v\n", rs)
	}
}

func (d *Debugger) StackTrace(threadId int) ([]StackFrame, error) {
	if d == nil || d.session == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	t, err := d.session.thread(threadId)
	if err != nil {
		return nil, err
	}

	threadFrames := d.session.framesByThread[t.id]
	if threadFrames == nil {
		threadFrames = []*frameInfo{}
	}

	stackIndex := 0
	if len(threadFrames) > 0 {
		stackIndex = threadFrames[len(threadFrames)-1].stackIndex
	}
	newEvents := t.stackEvents(stackIndex + 1)
	for _, e := range newEvents {
		stackIndex++
		info := d.session.newStackFrame(e, t, stackIndex)
		threadFrames = append(threadFrames, info)
	}
	d.session.framesByThread[t.id] = threadFrames

	frames := make([]StackFrame, 0, len(threadFrames))
	for _, info := range threadFrames {
		frames = append(frames, *info.frame)
	}
	slices.Reverse(frames)

	return frames, nil
}

func (s *session) newStackFrame(e *topdown.Event, t *thread, stackIndex int) *frameInfo {
	id := len(s.frames) + 1 // frames are 1-indexed

	var expl string
	if e.Node != nil {
		pretty := new(bytes.Buffer)
		topdown.PrettyTrace(pretty, []*topdown.Event{e})
		expl = pretty.String()
	} else {
		expl = fmt.Sprintf("%s, %s", e.Op, e.Location)
	}

	frame := &StackFrame{
		Id:       id,
		Name:     fmt.Sprintf("#%d: %d %s", id, e.QueryID, expl),
		Location: e.Location,
	}

	info := &frameInfo{
		stackIndex: stackIndex,
		threadId:   t.id,
		frame:      frame,
	}
	s.frames = append(s.frames, info)
	return info
}

func (s *session) frame(id int) (*frameInfo, error) {
	index := id - 1
	if index < 0 || index >= len(s.frames) {
		return nil, fmt.Errorf("invalid frame id: %d", id)
	}
	return s.frames[index], nil
}

func (d *Debugger) Scopes(frameId int) ([]Scope, error) {
	if d == nil || d.session == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	f, err := d.session.frame(frameId)
	if err != nil {
		return nil, err
	}

	t, err := d.session.thread(f.threadId)
	if err != nil {
		return nil, err
	}

	return t.scopes(f.stackIndex), nil
}

func (d *Debugger) Variables(varRef int) ([]Variable, error) {
	if d == nil || d.session == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	d.logger.Debug("Variables requested: %d", varRef)

	vars, err := d.varManager.vars(varRef)
	if err != nil {
		return nil, err
	}

	return vars, nil
}

func (d *Debugger) SetBreakpoints(locations []location.Location) ([]Breakpoint, error) {
	if d == nil || d.session == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	d.logger.Debug("Clearing existing breakpoints")
	d.session.breakpoints.clear()

	bps := make([]Breakpoint, 0, len(locations))
	for _, loc := range locations {
		bps = append(bps, d.session.breakpoints.add(loc))
	}

	return bps, nil
}

func (d *Debugger) Terminate() error {
	if d == nil || d.session == nil {
		return fmt.Errorf("no active debug session")
	}

	err := d.session.terminate()
	d.session = nil
	return err
}

func (s *session) terminate() error {
	if s == nil {
		return fmt.Errorf("no active debug session")
	}

	s.cancel()

	var hasErrors bool
	for _, t := range s.threads {
		if err := t.stop(); err != nil {
			hasErrors = true
			s.d.logger.Error("Failed to stop thread %d: %v", t.id, err)
		} else {
			s.d.eventHandler(ThreadEventType, t.id, "exited")
		}
	}

	if !hasErrors {
		s.d.eventHandler(TerminatedEventType, 0, "")
	}

	return nil
}
