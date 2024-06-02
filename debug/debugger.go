// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/go-dap"
	"github.com/open-policy-agent/opa/logging"
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

	// Threads are 1-indexed.
	t := newThread(1, "main")
	d.session = newSession(d, []*thread{t})
	d.session.start(d.ctx)
	return nil
}

func (d *Debugger) launchTestSession(props launchProperties) error {
	if d.session != nil {
		return fmt.Errorf("debug session already active")
	}

	return fmt.Errorf("test launch not supported")
}

type session struct {
	d       *Debugger
	threads []*thread
}

func newSession(debugger *Debugger, threads []*thread) *session {
	return &session{
		d:       debugger,
		threads: threads,
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
				if !t.stopped {
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

	err := s.threads[threadIndex].stepIn()

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
