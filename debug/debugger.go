// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/google/go-dap"
	fileurl "github.com/open-policy-agent/opa/internal/file/url"
	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
)

type Debugger struct {
	ctx                context.Context
	session            *session
	protocolManager    *protocolManager
	serverCapabilities dap.Capabilities
	clientCapabilities dap.InitializeRequestArguments
	logger             *debugLogger
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
		logger: newDebugLogger(logging.NewNoOpLogger(), logging.Info),
	}

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
	case *dap.DisconnectRequest:
		return true, newDisconnectResponse(), nil
	case *dap.InitializeRequest:
		resp, err = d.initialize(request)
	case *dap.LaunchRequest:
		resp, err = d.launch(request)
	case *dap.NextRequest:
		resp, err = d.session.next(request)
	case *dap.StackTraceRequest:
		resp, err = d.session.stackTrace(request)
	case *dap.ThreadsRequest:
		resp, err = d.session.getThreads(request)
	default:
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
	return &dap.AttachResponse{}, nil
}

type launchProperties struct {
	//Args        []string `json:"args"`
	BundlePaths []string `json:"bundles"`
	Command     string   `json:"command"`
	DataPaths   []string `json:"data"`
	InputPath   string   `json:"input"`
	LogLevel    string   `json:"log_level"`
	Query       string   `json:"query"`
	StopOnEnd   bool     `json:"stop_on_end"`
	StopOnEntry bool     `json:"stop_on_entry"`
	StopOnFail  bool     `json:"stop_on_fail"`
	Workspace   string   `json:"workspace"`
}

func (d *Debugger) launch(r *dap.LaunchRequest) (*dap.LaunchResponse, error) {
	var props launchProperties
	if err := json.Unmarshal(r.Arguments, &props); err != nil {
		return newLaunchResponse(), fmt.Errorf("invalid launch properties: %v", err)
	}

	if props.LogLevel != "" {
		d.logger.setLevelFromString(props.LogLevel)
	}

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

	return newLaunchResponse(), err
}

func (d *Debugger) launchRunSession(props launchProperties) error {
	if d.session != nil {
		return fmt.Errorf("debug session already active")
	}

	regoArgs := []func(*rego.Rego){
		rego.Query(props.Query),
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

	go func() {
		rs, err := pq.Eval(d.ctx, evalArgs...)
		if err != nil {
			d.logger.Error("Evaluation failed: %v", err)
			return
		}

		if rsJson, err := json.MarshalIndent(rs, "", "  "); err == nil {
			d.logger.Info("Result: %s\n", rsJson)
			d.protocolManager.sendEvent(newOutputEvent("stdout", string(rsJson)))
		} else {
			d.logger.Info("Result: %v\n", rs)
		}

		tracer.resultSet = rs
		_ = tracer.Close()
	}()

	// Threads are 1-indexed.
	t := newThread(1, "main", tracer, d.logger)
	d.session = newSession(d, props, []*thread{t})
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

type session struct {
	d              *Debugger
	properties     launchProperties
	threads        []*thread
	frames         []*frameInfo
	framesByThread map[int][]*frameInfo
}

func newSession(debugger *Debugger, props launchProperties, threads []*thread) *session {
	return &session{
		d:              debugger,
		properties:     props,
		threads:        threads,
		frames:         []*frameInfo{},
		framesByThread: map[int][]*frameInfo{},
	}
}

func (s *session) start(ctx context.Context) {
	for _, t := range s.threads {
		t := t
		go func() {
			s.d.protocolManager.sendEvent(newThreadEvent(t.id, "started"))
			if err := t.run(ctx); err != nil {
				s.d.logger.Error("Thread %d failed: %v", t.id, err)
				s.d.protocolManager.sendEvent(newThreadEvent(t.id, "exited"))
			}

			for _, t := range s.threads {
				if !t.done() {
					return
				}
			}
			s.d.protocolManager.sendEvent(newTerminatedEvent())
		}()
	}
}

func (s *session) next(r *dap.NextRequest) (*dap.NextResponse, error) {
	if s == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	threadIndex := r.Arguments.ThreadId - 1
	if threadIndex < 0 || threadIndex >= len(s.threads) {
		return nil, fmt.Errorf("invalid thread id: %d", r.Arguments.ThreadId)
	}

	t := s.threads[threadIndex]
	err := t.stepIn()
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
	entered bool
}

func (s *session) handleEvent(t *thread, e *topdown.Event, ts threadState) (bool, threadState, error) {
	state, ok := ts.(*sessionThreadState)
	if state != nil && !ok {
		s.d.logger.Warn("invalid thread state: %v", s)
	}
	if state == nil {
		state = &sessionThreadState{}
	}

	if s.properties.StopOnEntry && !state.entered && e.Location.File != "" {
		state.entered = true
		s.d.logger.Info("Thread %d stopped at entry", t.id)
		s.d.protocolManager.sendEvent(newStoppedEntryEvent(t.id))
		return true, state, nil
	}

	return false, state, nil
}

func (s *session) stackTrace(request *dap.StackTraceRequest) (*dap.StackTraceResponse, error) {
	if s == nil {
		return nil, fmt.Errorf("no active debug session")
	}

	threadIndex := request.Arguments.ThreadId - 1
	if threadIndex < 0 || threadIndex >= len(s.threads) {
		return nil, fmt.Errorf("invalid thread id: %d", request.Arguments.ThreadId)
	}

	t := s.threads[threadIndex]

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
