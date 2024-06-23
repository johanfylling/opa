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
	"io"
	"os"
	"slices"

	"github.com/google/go-dap"
	fileurl "github.com/open-policy-agent/opa/internal/file/url"
	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
	prnt "github.com/open-policy-agent/opa/topdown/print"
)

type Debugger struct {
	ctx                context.Context
	session            *session
	protocolManager    *protocolManager
	serverCapabilities dap.Capabilities
	clientCapabilities dap.InitializeRequestArguments
	logger             *debugLogger
	printHook          *printHook
	varManager         *variableManager
}

type printHook struct {
	prnt.Hook
	d *Debugger
}

func (h *printHook) Print(_ prnt.Context, str string) error {
	if h == nil || h.d == nil {
		return nil
	}
	h.d.protocolManager.sendEvent(newOutputEvent("stdout", str))
	return nil
}

func NewDebugger(options ...func(*Debugger)) *Debugger {
	d := &Debugger{
		serverCapabilities: dap.Capabilities{
			SupportsBreakpointLocationsRequest:    true,
			SupportsCancelRequest:                 true,
			SupportsConfigurationDoneRequest:      true,
			SupportsSingleThreadExecutionRequests: true,
			SupportSuspendDebuggee:                true,
			SupportTerminateDebuggee:              true,
			SupportsTerminateRequest:              true,
		},
		varManager: newVariableManager(),
		logger:     newDebugLogger(logging.NewNoOpLogger(), logging.Info),
	}
	d.printHook = &printHook{d: d}

	for _, option := range options {
		option(d)
	}

	return d
}

func Logger(logger logging.Logger) func(*Debugger) {
	return func(d *Debugger) {
		d.logger = newDebugLogger(logger, logger.GetLevel())
	}
}

func (d *Debugger) Start(ctx context.Context, conn io.ReadWriteCloser) error {
	d.ctx = ctx
	d.protocolManager = newProtocolManager(d.logger.local)
	d.logger.protocolManager = d.protocolManager
	return d.protocolManager.Start(ctx, conn, d.handleMessage)
}

func (d *Debugger) handleMessage(message dap.Message) (bool, dap.ResponseMessage, error) {
	var resp dap.ResponseMessage
	var err error
	switch request := message.(type) {
	case *dap.AttachRequest:
		resp, err = d.attach(request)
	case *dap.BreakpointLocationsRequest:
		resp, err = d.session.breakpointLocations(request)
	case *dap.ConfigurationDoneRequest:
		// FIXME: Is this when we should start eval?
		resp = newConfigurationDoneResponse()
	case *dap.ContinueRequest:
		resp, err = d.session.resume(request)
	case *dap.DisconnectRequest:
		return true, newDisconnectResponse(), nil
	case *dap.EvaluateRequest:
		resp, err = d.session.evaluate(request)
	case *dap.InitializeRequest:
		resp, err = d.initialize(request)
	case *dap.LaunchRequest:
		resp, err = d.launch(request)
	case *dap.NextRequest:
		resp, err = d.session.next(request)
	case *dap.ScopesRequest:
		resp, err = d.session.scopes(request)
	case *dap.SetBreakpointsRequest:
		resp, err = d.session.setBreakpoints(request)
	case *dap.StackTraceRequest:
		resp, err = d.session.stackTrace(request)
	case *dap.StepInRequest:
		resp, err = d.session.stepIn(request)
	case *dap.StepOutRequest:
		resp, err = d.session.stepOut(request)
	case *dap.TerminateRequest:
		resp, err = d.terminate(request)
	case *dap.ThreadsRequest:
		resp, err = d.session.getThreads(request)
	case *dap.VariablesRequest:
		resp, err = d.session.variables(request)
	default:
		d.logger.Warn("Handler not found for request: %T", message)
		err = fmt.Errorf("handler not found for request: %T", message)
	}
	return false, resp, err
}

func (d *Debugger) initialize(r *dap.InitializeRequest) (*dap.InitializeResponse, error) {
	if args, err := json.Marshal(r.Arguments); err == nil {
		d.logger.Info("Initializing: %s", args)
	} else {
		d.logger.Info("Initializing")
	}

	d.clientCapabilities = r.Arguments

	return newInitializeResponse(d.serverCapabilities), nil
}

func (d *Debugger) attach(r *dap.AttachRequest) (*dap.AttachResponse, error) {
	return newAttachResponse(), fmt.Errorf("attach not supported")
}

type launchProperties struct {
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

func (lp launchProperties) String() string {
	b, err := json.Marshal(lp)
	if err != nil {
		return fmt.Sprintf("{}")
	}
	return string(b)
}

func (d *Debugger) launch(r *dap.LaunchRequest) (*dap.LaunchResponse, error) {
	var props launchProperties
	if err := json.Unmarshal(r.Arguments, &props); err != nil {
		return newLaunchResponse(), fmt.Errorf("invalid launch properties: %v", err)
	}

	if props.LogLevel != "" {
		d.logger.setLevelFromString(props.LogLevel)
	} else {
		d.logger.setRemoteEnabled(false)
	}

	if props.SkipOps == nil {
		props.SkipOps = []topdown.Op{topdown.IndexOp, topdown.RedoOp, topdown.SaveOp, topdown.UnifyOp}
	}

	d.logger.Info("Launching: %s", props)

	var err error
	switch props.Command {
	case "run":
		err = d.launchRunSession(props)
	case "test":
		err = d.launchTestSession(props)
	case "":
		err = fmt.Errorf("missing launch command")
	default:
		err = fmt.Errorf("unsupported launch command: '%s'", r.Command)
	}

	if err == nil {
		d.protocolManager.sendEvent(newInitializedEvent())
	}

	return newLaunchResponse(), err
}

func (d *Debugger) launchRunSession(props launchProperties) error {
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
	d.session = newSession(d, props, []*thread{t})

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

	t.eventHandler = d.session.handleEvent
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

func (d *Debugger) launchTestSession(props launchProperties) error {
	if d.session != nil {
		return fmt.Errorf("debug session already active")
	}

	return fmt.Errorf("test launch not supported")
}

type frameInfo struct {
	frame      *dap.StackFrame
	threadId   int
	stackIndex int
}

type breakpointList []dap.Breakpoint

func (b breakpointList) String() string {
	if b == nil {
		return "[]"
	}

	buf := new(bytes.Buffer)
	buf.WriteString("[")
	for i, bp := range b {
		if i > 0 {
			buf.WriteString(", ")
		}
		_, _ = fmt.Fprintf(buf, "%s:%d", bp.Source.Path, bp.Line)
	}
	buf.WriteString("]")
	return buf.String()
}

type breakpointCollection struct {
	breakpoints map[string]breakpointList
	idCounter   int
}

func newBreakpointCollection() *breakpointCollection {
	return &breakpointCollection{
		breakpoints: map[string]breakpointList{},
	}
}

func (bc *breakpointCollection) newId() int {
	bc.idCounter++
	return bc.idCounter
}

func (bc *breakpointCollection) add(bp dap.Breakpoint) {
	bp.Id = bc.newId()
	bps := bc.breakpoints[bp.Source.Path]
	bps = append(bps, bp)
	bc.breakpoints[bp.Source.Path] = bps
}

func (bc *breakpointCollection) allForSource(s *dap.Source) breakpointList {
	return bc.allForFilePath(s.Path)
}

func (bc *breakpointCollection) allForFilePath(path string) breakpointList {
	return bc.breakpoints[path]
}

func (bc *breakpointCollection) clear() {
	bc.breakpoints = map[string]breakpointList{}
}

func (bc *breakpointCollection) String() string {
	if bc == nil {
		return "[]"
	}

	buf := new(bytes.Buffer)
	buf.WriteString("[")
	for path, bps := range bc.breakpoints {
		for i, bp := range bps {
			if i > 0 {
				buf.WriteString(", ")
			}
			_, _ = fmt.Fprintf(buf, "%s:%d\n", path, bp.Line)
		}
	}
	buf.WriteString("]")
	return buf.String()
}

type session struct {
	d              *Debugger
	properties     launchProperties
	threads        []*thread
	frames         []*frameInfo
	framesByThread map[int][]*frameInfo
	breakpoints    *breakpointCollection
	ctx            context.Context
	cancel         context.CancelFunc
}

func newSession(debugger *Debugger, props launchProperties, threads []*thread) *session {
	ctx, cancel := context.WithCancel(debugger.ctx)
	return &session{
		d:              debugger,
		properties:     props,
		threads:        threads,
		frames:         []*frameInfo{},
		framesByThread: map[int][]*frameInfo{},
		breakpoints:    newBreakpointCollection(),
		ctx:            ctx,
		cancel:         cancel,
	}
}

func (s *session) start(ctx context.Context) {
	for _, t := range s.threads {
		t := t
		go func() {
			s.d.protocolManager.sendEvent(newThreadEvent(t.id, "started"))
			if err := t.run(ctx); err != nil {
				s.d.logger.Error("Thread %d failed: %v", t.id, err)
			}
			s.d.protocolManager.sendEvent(newThreadEvent(t.id, "exited"))

			for _, t := range s.threads {
				if !t.done() {
					return
				}
			}
			s.d.protocolManager.sendEvent(newTerminatedEvent())
		}()
	}
}

func (s *session) thread(id int) (*thread, error) {
	index := id - 1
	if index < 0 || index >= len(s.threads) {
		return nil, fmt.Errorf("invalid thread id: %d", id)
	}
	return s.threads[index], nil
}

func (s *session) resume(r *dap.ContinueRequest) (*dap.ContinueResponse, error) {
	if s == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	t, err := s.thread(r.Arguments.ThreadId)
	if err != nil {
		return nil, err
	}
	t.resume()
	return &dap.ContinueResponse{}, nil
}

func (s *session) next(r *dap.NextRequest) (*dap.NextResponse, error) {
	if s == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	t, err := s.thread(r.Arguments.ThreadId)
	if err != nil {
		return nil, err
	}

	err = t.stepOver()
	if err == nil {
		s.d.protocolManager.sendEvent(newStoppedEntryEvent(t.id))
	}
	if t.done() {
		s.d.protocolManager.sendEvent(newThreadEvent(t.id, "exited"))
		allStopped := true
		for _, t := range s.threads {
			if !t.done() {
				allStopped = false
				break
			}
		}
		if allStopped {
			s.d.protocolManager.sendEvent(newTerminatedEvent())
		}
	}

	return &dap.NextResponse{}, err
}

func (s *session) stepIn(r *dap.StepInRequest) (*dap.StepInResponse, error) {
	if s == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	t, err := s.thread(r.Arguments.ThreadId)
	if err != nil {
		return nil, err
	}

	err = t.stepIn()
	if err == nil {
		s.d.protocolManager.sendEvent(newStoppedEntryEvent(t.id))
	}
	if t.done() {
		s.d.protocolManager.sendEvent(newThreadEvent(t.id, "exited"))
		allStopped := true
		for _, t := range s.threads {
			if !t.done() {
				allStopped = false
				break
			}
		}
		if allStopped {
			s.d.protocolManager.sendEvent(newTerminatedEvent())
		}
	}

	return &dap.StepInResponse{}, err
}

func (s *session) stepOut(r *dap.StepOutRequest) (*dap.StepOutResponse, error) {
	if s == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	t, err := s.thread(r.Arguments.ThreadId)
	if err != nil {
		return nil, err
	}

	err = t.stepOut()
	if err == nil {
		s.d.protocolManager.sendEvent(newStoppedEntryEvent(t.id))
	}
	if t.done() {
		s.d.protocolManager.sendEvent(newThreadEvent(t.id, "exited"))
		allStopped := true
		for _, t := range s.threads {
			if !t.done() {
				allStopped = false
				break
			}
		}
		if allStopped {
			s.d.protocolManager.sendEvent(newTerminatedEvent())
		}
	}

	return &dap.StepOutResponse{}, err
}

func (s *session) getThreads(_ *dap.ThreadsRequest) (*dap.ThreadsResponse, error) {
	if s == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	threads := make([]dap.Thread, 0, len(s.threads))
	for _, t := range s.threads {
		threads = append(threads, dap.Thread{
			Id:   t.id,
			Name: t.name,
		})
	}

	return newThreadsResponse(threads), nil
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
			s.d.protocolManager.sendEvent(newStoppedResultEvent(t.id))
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
		s.d.protocolManager.sendEvent(newStoppedEntryEvent(t.id))
		return breakAction, state, nil
	}

	if s.properties.StopOnFail && e.Op == topdown.FailOp {
		s.d.logger.Info("Thread %d stopped on failure", t.id)
		s.d.protocolManager.sendEvent(newStoppedExceptionEvent(t.id, string(e.Op)))
		return breakAction, state, nil
	}

	if e.Location != nil && e.Location.File != "" {
		for _, bp := range s.breakpoints.allForFilePath(e.Location.File) {
			if bp.Line == e.Location.Row {
				s.d.logger.Info("Thread %d stopped at breakpoint: %s:%d", t.id, e.Location.File, e.Location.Row)
				s.d.protocolManager.sendEvent(newStoppedBreakpointEvent(t.id, &bp))
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
		s.d.protocolManager.sendEvent(newOutputEvent("stdout", string(rsJson)))
	} else {
		s.d.logger.Debug("Result: %v\n", rs)
	}
}

func (s *session) stackTrace(r *dap.StackTraceRequest) (*dap.StackTraceResponse, error) {
	if s == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	t, err := s.thread(r.Arguments.ThreadId)
	if err != nil {
		return nil, err
	}

	threadFrames := s.framesByThread[t.id]
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
		info := s.newStackFrame(e, t, stackIndex)
		threadFrames = append(threadFrames, info)
	}
	s.framesByThread[t.id] = threadFrames

	frames := make([]dap.StackFrame, 0, len(threadFrames))
	for _, info := range threadFrames {
		frames = append(frames, *info.frame)
	}
	slices.Reverse(frames)

	return newStackTraceResponse(frames), nil
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

	var source *dap.Source
	line := 1
	if e.Location != nil {
		line = e.Location.Row
		if e.Location.File != "" {
			source = &dap.Source{
				Path: e.Location.File,
			}
		}
	}

	frame := &dap.StackFrame{
		Id:     id,
		Name:   fmt.Sprintf("#%d: %d %s", id, e.QueryID, expl),
		Line:   line,
		Source: source,
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

func (s *session) evaluate(_ *dap.EvaluateRequest) (*dap.EvaluateResponse, error) {
	return newEvaluateResponse(""), fmt.Errorf("evaluate not supported")
}

func (s *session) scopes(request *dap.ScopesRequest) (*dap.ScopesResponse, error) {
	if s == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	f, err := s.frame(request.Arguments.FrameId)
	if err != nil {
		return nil, err
	}

	t, err := s.thread(f.threadId)
	if err != nil {
		return nil, err
	}

	return newScopesResponse(t.scopes(f.stackIndex)), nil
}

func (s *session) variables(request *dap.VariablesRequest) (*dap.VariablesResponse, error) {
	if s == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	varRef := request.Arguments.VariablesReference
	s.d.logger.Debug("Variables requested: %d", varRef)

	vars, err := s.d.varManager.vars(request.Arguments.VariablesReference)
	if err != nil {
		return nil, err
	}

	return newVariablesResponse(vars), nil
}

func (s *session) breakpointLocations(request *dap.BreakpointLocationsRequest) (*dap.BreakpointLocationsResponse, error) {
	if s == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	line := request.Arguments.Line
	s.d.logger.Debug("Breakpoint locations requested for: %s:%d", request.Arguments.Source.Name, line)

	// TODO: Actually assert where breakpoints can be placed.
	return newBreakpointLocationsResponse([]dap.BreakpointLocation{
		{
			Line:   line,
			Column: 1,
		},
	}), nil
}

func (s *session) setBreakpoints(request *dap.SetBreakpointsRequest) (*dap.SetBreakpointsResponse, error) {
	if s == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	source := request.Arguments.Source
	s.d.logger.Debug("Clearing existing breakpoints for source %s: %v",
		source.Name, s.breakpoints.allForSource(&source))
	s.breakpoints.clear()

	for _, bp := range request.Arguments.Breakpoints {
		s.breakpoints.add(dap.Breakpoint{
			Source:   &request.Arguments.Source,
			Verified: true,
			Line:     bp.Line,
			Column:   bp.Column,
		})
	}

	return newSetBreakpointsResponse(s.breakpoints.allForSource(&source)), nil
}

func (d *Debugger) terminate(r *dap.TerminateRequest) (*dap.TerminateResponse, error) {
	resp, err := d.session.terminate(r)
	d.session = nil
	return resp, err
}

func (s *session) terminate(_ *dap.TerminateRequest) (*dap.TerminateResponse, error) {
	if s == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	s.cancel()

	var hasErrors bool
	for _, t := range s.threads {
		if err := t.stop(); err != nil {
			hasErrors = true
			s.d.logger.Error("Failed to stop thread %d: %v", t.id, err)
		} else {
			s.d.protocolManager.sendEvent(newThreadEvent(t.id, "exited"))
		}
	}

	if !hasErrors {
		s.d.protocolManager.sendEvent(newTerminatedEvent())
	}

	return newTerminateResponse(), nil
}
