// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import (
	"github.com/open-policy-agent/opa/ast/location"
)

type StackFrame struct {
	Id       int
	Name     string
	Location *location.Location
}

type frameInfo struct {
	frame      *StackFrame
	threadId   int
	stackIndex int
}