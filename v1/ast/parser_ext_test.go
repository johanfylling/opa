// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast_test

import (
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/format"
)

func TestParseModule_DefaultRegoVersion(t *testing.T) {
	tests := []struct {
		note     string
		mod      string
		expRules []string
		expErrs  []string
	}{
		{
			note: "v0", // NOT default rego-version
			mod: `package test
				p[x] { 
					x = "a"
				}`,
			expErrs: []string{
				"test.rego:2: rego_parse_error: `if` keyword is required before rule body",
				"test.rego:2: rego_parse_error: `contains` keyword is required for partial set rules",
			},
		},
		{
			note: "import rego.v1",
			mod: `package test
				import rego.v1
				
				p contains x if { 
					x = "a"
				}`,
			expRules: []string{"p"},
		},
		{
			note: "v1", // default rego-version
			mod: `package test
				p contains x if { 
					x = "a"
				}`,
			expRules: []string{"p"},
		},
		{
			note: "import rego.v2",
			mod: `package test
				import rego.v2
				
				p contains x if { 
					x = "a"
				}`,
			expErrs: []string{
				"test.rego:2: rego_parse_error: invalid import, `rego.v2` is not supported by current capabilities",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			m, err := ast.ParseModule("test.rego", tc.mod)

			if len(tc.expErrs) > 0 {
				for _, expErr := range tc.expErrs {
					if !strings.Contains(err.Error(), expErr) {
						t.Fatalf("Expected error to contain:\n\n%s\n\ngot:\n\n%s", expErr, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %s", err)
				}

				if len(m.Rules) != len(tc.expRules) {
					t.Fatalf("Expected %d rules, got %d", len(tc.expRules), len(m.Rules))
				}
				for i, r := range m.Rules {
					if r.Head.Name.String() != tc.expRules[i] {
						t.Fatalf("Expected rule %q, got %q", tc.expRules[i], r.Head.Name.String())
					}
				}
			}
		})
	}
}

func TestParseModule(t *testing.T) {
	tests := []struct {
		note          string
		mod           string
		parserOptions *ast.ParserOptions
		expRules      []string
		expErrs       []string
	}{
		{
			note: "v0",
			mod: `package test
				
				p[x] { 
					x = "a"
				}`,
			parserOptions: &ast.ParserOptions{RegoVersion: ast.RegoV0},
			expRules:      []string{"p"},
		},
		{
			note: "v1",
			mod: `package test
				
				p contains x if { 
					x = "a"
				}`,
			parserOptions: &ast.ParserOptions{RegoVersion: ast.RegoV1},
			expRules:      []string{"p"},
		},
		{
			note: "v2",
			mod: `package test
				
				p contains x if { 
					x = "a"
				}`,
			parserOptions: func() *ast.ParserOptions {
				caps := ast.CapabilitiesForThisVersion()
				caps.Features = append(caps.Features, ast.FeatureRegoV2Import)
				return &ast.ParserOptions{
					RegoVersion:  ast.RegoV2,
					Capabilities: caps,
				}
			}(),
			expRules: []string{"p"},
		},
		{
			note: "import rego.v2, no capability",
			mod: `package test
				import rego.v2
				
				p contains x if { 
					x = "a"
				}`,
			expErrs: []string{
				"test.rego:2: rego_parse_error: invalid import, `rego.v2` is not supported by current capabilities",
			},
		},
		{
			note: "import rego.v2, with capability",
			mod: `package test
				import rego.v2
				
				p contains x if { 
					x = "a"
				}`,
			parserOptions: func() *ast.ParserOptions {
				caps := ast.CapabilitiesForThisVersion()
				caps.Features = append(caps.Features, ast.FeatureRegoV2Import)
				return &ast.ParserOptions{Capabilities: caps}
			}(),
			expRules: []string{"p"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			var popts ast.ParserOptions
			if tc.parserOptions != nil {
				popts = *tc.parserOptions
			} else {
				popts = ast.ParserOptions{}
			}

			m, err := ast.ParseModuleWithOpts("test.rego", tc.mod, popts)

			if len(tc.expErrs) > 0 {
				if err == nil {
					t.Fatalf("Expected error(s):\n\n%v\n\ngot: nil", err)
				}

				for _, expErr := range tc.expErrs {
					if !strings.Contains(err.Error(), expErr) {
						t.Fatalf("Expected error to contain:\n\n%s\n\ngot:\n\n%s", expErr, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %s", err)
				}

				if len(m.Rules) != len(tc.expRules) {
					t.Fatalf("Expected %d rules, got %d", len(tc.expRules), len(m.Rules))
				}
				for i, r := range m.Rules {
					if r.Head.Name.String() != tc.expRules[i] {
						t.Fatalf("Expected rule %q, got %q", tc.expRules[i], r.Head.Name.String())
					}
				}
			}
		})
	}
}

func TestParseBody_DefaultRegoVersion(t *testing.T) {
	tests := []struct {
		note       string
		body       string
		expStmts   int
		assertSame bool
	}{
		{
			note: "v0", // default rego-version
			body: `x := ["a", "b", "c"][i]
`,
			expStmts:   1,
			assertSame: true,
		},
		{
			note: "v1", // NOT default rego-version
			body: `some x, i in ["a", "b", "c"]
`,
			expStmts:   1,
			assertSame: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			body, err := ast.ParseBody(tc.body)

			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}

			if len(body) != tc.expStmts {
				t.Fatalf("Expected %d statements, got %d:%q\n\n", tc.expStmts, len(body), body)
			}

			if tc.assertSame {
				formatted, err := format.AstWithOpts(body, format.Opts{RegoVersion: ast.RegoV1}) // every body is v1-compatible
				if err != nil {
					t.Fatalf("Unexpected error: %s", err)
				}

				if strings.Compare(string(formatted), tc.body) != 0 {
					t.Fatalf("Expected body to be %q, got %q", tc.body, string(formatted))
				}
			}
		})
	}
}
