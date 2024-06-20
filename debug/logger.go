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
	remoteEnabled   bool
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
	l.send(logging.Debug, fmt, a...)
}

func (l *debugLogger) Info(fmt string, a ...interface{}) {
	if l == nil {
		return
	}
	l.local.Info(fmt, a...)
	l.send(logging.Info, fmt, a...)
}

func (l *debugLogger) Error(fmt string, a ...interface{}) {
	if l == nil {
		return
	}
	l.local.Error(fmt, a...)
	l.send(logging.Error, fmt, a...)
}

func (l *debugLogger) Warn(fmt string, a ...interface{}) {
	if l == nil {
		return
	}
	l.local.Warn(fmt, a...)
	l.send(logging.Warn, fmt, a...)
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

func (l *debugLogger) setRemoteEnabled(enabled bool) {
	if l == nil {
		return
	}
	l.remoteEnabled = enabled
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

	l.remoteEnabled = true

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

func (l *debugLogger) send(level logging.Level, fmt string, a ...interface{}) {
	if l == nil || l.protocolManager == nil || !l.remoteEnabled || level > l.level {
		return
	}

	var levelStr string
	switch level {

	case logging.Error:
		levelStr = "ERROR"
	case logging.Warn:
		levelStr = "WARN"
	case logging.Info:
		levelStr = "INFO"
	case logging.Debug:
		levelStr = "DEBUG"
	default:
		levelStr = "UNKNOWN"
	}

	message := strFmt.Sprintf(fmt, a...)
	output := strFmt.Sprintf("%s: %s\n", levelStr, message)
	l.protocolManager.sendEvent(newOutputEvent("console", output))
}
