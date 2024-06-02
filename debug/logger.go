// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import (
	strFmt "fmt"

	"github.com/open-policy-agent/opa/logging"
)

type debugLogger struct {
	local           logging.Logger
	level           logging.Level
	protocolManager *protocolManager
}

func newDebugLogger(localLogger logging.Logger, level logging.Level) *debugLogger {
	return &debugLogger{
		local: localLogger,
		level: level,
	}
}

func (l *debugLogger) Debug(fmt string, a ...interface{}) {
	if l == nil {
		return
	}
	l.local.Debug(fmt, a...)
	l.send("DEBUG", fmt, a...)
}

func (l *debugLogger) Info(fmt string, a ...interface{}) {
	if l == nil {
		return
	}
	l.local.Info(fmt, a...)
	l.send("INFO", fmt, a...)
}

func (l *debugLogger) Error(fmt string, a ...interface{}) {
	if l == nil {
		return
	}
	l.local.Error(fmt, a...)
	l.send("ERROR", fmt, a...)
}

func (l *debugLogger) Warn(fmt string, a ...interface{}) {
	if l == nil {
		return
	}
	l.local.Warn(fmt, a...)
	l.send("WARN", fmt, a...)
}

func (l *debugLogger) WithFields(map[string]interface{}) logging.Logger {
	if l == nil {
		return nil
	}
	return l
}

func (l *debugLogger) GetLevel() logging.Level {
	if l == nil {
		return 0
	}
	if l.local.GetLevel() > l.level {
		return l.level
	}
	return l.level
}

func (l *debugLogger) SetLevel(level logging.Level) {
	if l == nil {
		return
	}
	l.level = level
}

func (l *debugLogger) setLevelFromString(level string) {
	if l == nil {
		return
	}

	switch level {
	case "error":
		l.level = logging.Error
	case "warn":
		l.level = logging.Warn
	case "info":
		l.level = logging.Info
	case "debug":
		l.level = logging.Debug
	}
}

func (l *debugLogger) send(level string, fmt string, a ...interface{}) {
	if l == nil || l.protocolManager == nil {
		return
	}

	message := strFmt.Sprintf(fmt, a...)
	output := strFmt.Sprintf("%s: %s\n", level, message)
	l.protocolManager.sendEvent(newOutputEvent("console", output))
}
