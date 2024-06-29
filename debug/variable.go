// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package debug

import (
	"fmt"
	"slices"
	"strings"

	"github.com/open-policy-agent/opa/ast"
)

type namedVar struct {
	Name  string
	Value ast.Value
}

type variableGetter func() []namedVar

type variableManager struct {
	getters []variableGetter
}

func newVariableManager() *variableManager {
	return &variableManager{}
}

func (vs *variableManager) addVars(getter variableGetter) int {
	vs.getters = append(vs.getters, getter)
	return len(vs.getters)
}

type Variable struct {
	Name               string
	Type               string
	Value              string
	VariablesReference int
}

func (vs *variableManager) vars(varRef int) ([]Variable, error) {
	i := varRef - 1
	if i < 0 || i >= len(vs.getters) {
		return nil, fmt.Errorf("invalid variable reference: %d", varRef)
	}

	namedVar := vs.getters[i]()
	vars := make([]Variable, len(namedVar))

	for i, nv := range namedVar {
		vars[i] = Variable{
			Name:               nv.Name,
			Type:               valueTypeName(nv.Value),
			Value:              truncatedString(nv.Value.String(), 100),
			VariablesReference: vs.subVars(nv.Value),
		}
	}

	slices.SortFunc(vars, func(a, b Variable) int {
		return strings.Compare(a.Name, b.Name)
	})

	return vars, nil
}

func truncatedString(s string, max int) string {
	if len(s) > max {
		return s[:max-2] + "..."
	}
	return s
}

func valueTypeName(v ast.Value) string {
	switch v.(type) {
	case ast.Null:
		return "null"
	case ast.Boolean:
		return "bool"
	case ast.Number:
		return "number"
	case ast.String:
		return "string"
	case *ast.Array:
		return "array"
	case ast.Object:
		return "object"
	case ast.Set:
		return "set"
	case ast.Ref:
		return "ref"
	default:
		return "unknown"
	}
}

func (vs *variableManager) subVars(v ast.Value) int {
	if obj, ok := v.(ast.Object); ok {
		vars := make([]namedVar, 0, obj.Len())
		if err := obj.Iter(func(k, v *ast.Term) error {
			vars = append(vars, namedVar{
				Name:  k.String(),
				Value: v.Value,
			})
			return nil
		}); err != nil {
			return 0
		}
		return vs.addVars(func() []namedVar {
			return vars
		})
	}

	if arr, ok := v.(*ast.Array); ok {
		vars := make([]namedVar, 0, arr.Len())
		for i := 0; i < arr.Len(); i++ {
			vars = append(vars, namedVar{
				Name:  fmt.Sprintf("%d", i),
				Value: arr.Elem(i).Value,
			})
		}
		return vs.addVars(func() []namedVar {
			return vars
		})
	}

	if set, ok := v.(ast.Set); ok {
		vars := make([]namedVar, 0, set.Len())
		for _, elem := range set.Slice() {
			vars = append(vars, namedVar{
				Value: elem.Value,
			})
		}
		return vs.addVars(func() []namedVar {
			return vars
		})
	}

	return 0
}
