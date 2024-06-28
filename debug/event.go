// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import "github.com/open-policy-agent/opa/topdown"

type EventType string

const (
	ExceptionEventType  = "exception"
	StdoutEventType     = "stdout"
	StoppedEventType    = "stopped"
	TerminatedEventType = "terminated"
	ThreadEventType     = "thread"
)

// FIXME: Rename?
type DebugEvent struct {
	Type       EventType
	Thread     int
	Message    string
	stackIndex int
	stackEvent *topdown.Event
}

type EventHandler func(DebugEvent)

func newNopEventHandler() EventHandler {
	return func(_ DebugEvent) {}
}
