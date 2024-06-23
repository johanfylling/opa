// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

type EventType string

const (
	ExceptionEventType  = "exception"
	StdoutEventType     = "stdout"
	StoppedEventType    = "stopped"
	TerminatedEventType = "terminated"
	ThreadEventType     = "thread"
)

type EventHandler func(eventType EventType, threadId int, text string)

func newNopEventHandler() EventHandler {
	return func(_ EventType, _ int, _ string) {}
}
