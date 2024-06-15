// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"sync"

	"github.com/google/go-dap"
	"github.com/open-policy-agent/opa/logging"
)

type messageHandler func(request dap.Message) (bool, dap.ResponseMessage, error)

type protocolManager struct {
	//handle  messageHandler
	inChan  chan dap.Message
	outChan chan dap.Message
	logger  logging.Logger
	seq     int
	seqLock sync.Mutex
}

func newProtocolManager(logger logging.Logger) *protocolManager {
	return &protocolManager{
		//handle:  handler,
		inChan:  make(chan dap.Message),
		outChan: make(chan dap.Message),
		logger:  logger,
	}
}

func (pm *protocolManager) Start(ctx context.Context, conn io.ReadWriteCloser, handle messageHandler) error {
	reader := bufio.NewReader(conn)
	done := make(chan error)

	go func() {
		for resp := range pm.outChan {
			if pm.logger.GetLevel() == logging.Debug {
				if respData, _ := json.Marshal(resp); respData != nil {
					pm.logger.Debug("Sending %T\n%s", resp, respData)
				} else {
					pm.logger.Debug("Sending %T", resp)
				}
			}
			if err := dap.WriteProtocolMessage(conn, resp); err != nil {
				done <- err
				return
			}
		}
	}()

	go func() {
		for {
			pm.logger.Debug("Waiting for message...")
			req, err := dap.ReadProtocolMessage(reader)
			if err != nil {
				done <- err
				return
			}

			if pm.logger.GetLevel() == logging.Debug {
				if reqData, _ := json.Marshal(req); reqData != nil {
					pm.logger.Debug("Received %T\n%s", req, reqData)
				} else {
					pm.logger.Debug("Received %T", req)
				}
			}

			stop, resp, err := handle(req)
			if err != nil {
				pm.logger.Warn("Error handling request: %v", err)
			}
			pm.sendResponse(resp, req, err)
			if stop {
				done <- err
				return
			}
		}
	}()

	for {
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (pm *protocolManager) sendEvent(e dap.EventMessage) {
	e.GetEvent().Seq = pm.nextSeq()
	pm.outChan <- e
}

func (pm *protocolManager) sendResponse(resp dap.ResponseMessage, req dap.Message, err error) {
	if resp == nil {
		return
	}

	if r := resp.GetResponse(); r != nil {
		r.Success = err == nil
		if err != nil {
			r.Message = err.Error()
		}
		r.Seq = pm.nextSeq()
		if req != nil {
			r.RequestSeq = req.GetSeq()
		}
	}
	pm.outChan <- resp
}

func (pm *protocolManager) Close() {
	close(pm.outChan)
	close(pm.inChan)
}

func (pm *protocolManager) nextSeq() int {
	if pm == nil {
		return 0
	}
	pm.seqLock.Lock()
	defer pm.seqLock.Unlock()
	pm.seq++
	return pm.seq
}

func newInitializeResponse(capabilities dap.Capabilities) *dap.InitializeResponse {
	return &dap.InitializeResponse{
		Response: dap.Response{
			ProtocolMessage: dap.ProtocolMessage{
				//Seq:  pm.nextSeq(),
				Type: "response",
			},
			Command: "initialize",
			//RequestSeq: r.GetSeq(),
			Success: true,
		},
		Body: capabilities,
	}
}

func newDisconnectResponse() *dap.DisconnectResponse {
	return &dap.DisconnectResponse{
		Response: dap.Response{
			ProtocolMessage: dap.ProtocolMessage{
				Type: "response",
			},
			Command: "disconnect",
			Success: true,
		},
	}
}

func newEvaluateResponse(value string) *dap.EvaluateResponse {
	return &dap.EvaluateResponse{
		Response: dap.Response{
			ProtocolMessage: dap.ProtocolMessage{
				Type: "response",
			},
			Command: "evaluate",
			Success: true,
		},
		Body: dap.EvaluateResponseBody{
			Result: value,
		},
	}
}

func newLaunchResponse() *dap.LaunchResponse {
	return &dap.LaunchResponse{
		Response: dap.Response{
			ProtocolMessage: dap.ProtocolMessage{
				Type: "response",
			},
			Command: "launch",
			Success: true,
		},
	}
}

func newStackTraceResponse(stack []dap.StackFrame) *dap.StackTraceResponse {
	return &dap.StackTraceResponse{
		Response: dap.Response{
			ProtocolMessage: dap.ProtocolMessage{
				Type: "response",
			},
			Command: "stackTrace",
			Success: true,
		},
		Body: dap.StackTraceResponseBody{
			StackFrames: stack,
			TotalFrames: len(stack),
		},
	}
}

func newThreadsResponse(threads []dap.Thread) *dap.ThreadsResponse {
	return &dap.ThreadsResponse{
		Response: dap.Response{
			ProtocolMessage: dap.ProtocolMessage{
				Type: "response",
			},
			Command: "threads",
			Success: true,
		},
		Body: dap.ThreadsResponseBody{
			Threads: threads,
		},
	}
}

// Events

func newOutputEvent(category string, output string) *dap.OutputEvent {
	return &dap.OutputEvent{
		Event: dap.Event{
			ProtocolMessage: dap.ProtocolMessage{
				Type: "event",
			},
			Event: "output",
		},
		Body: dap.OutputEventBody{
			Output:   output,
			Category: category,
		},
	}
}

func newThreadEvent(threadId int, reason string) *dap.ThreadEvent {
	return &dap.ThreadEvent{
		Event: dap.Event{
			ProtocolMessage: dap.ProtocolMessage{
				Type: "event",
			},
			Event: "thread",
		},
		Body: dap.ThreadEventBody{
			Reason:   reason,
			ThreadId: threadId,
		},
	}
}

func newTerminatedEvent() *dap.TerminatedEvent {
	return &dap.TerminatedEvent{
		Event: dap.Event{
			ProtocolMessage: dap.ProtocolMessage{
				Type: "event",
			},
			Event: "terminated",
		},
	}
}

func newStoppedEntryEvent(threadId int) *dap.StoppedEvent {
	return newStoppedEvent("entry", threadId, nil, "", "")
}

func newStoppedResultEvent(threadId int) *dap.StoppedEvent {
	return newStoppedEvent("result", threadId, nil, "", "")
}

func newStoppedEvent(reason string, threadId int, bps []int, description string, text string) *dap.StoppedEvent {
	return &dap.StoppedEvent{
		Event: dap.Event{
			ProtocolMessage: dap.ProtocolMessage{
				Type: "event",
			},
			Event: "stopped",
		},
		Body: dap.StoppedEventBody{
			Reason:            reason,
			ThreadId:          threadId,
			Text:              text,
			AllThreadsStopped: true,
			HitBreakpointIds:  bps,
			PreserveFocusHint: false,
		},
	}
}
