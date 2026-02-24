// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

import (
	"fmt"
	"strings"
)

// BodyMermaid returns a Mermaid flowchart diagram representing the structure of
// the given Body. The diagram is intended to give a readable overview of the
// expression tree.
//
// This function is intended for debug purposes when inspecting ASTs.
func BodyMermaid(body Body) string {
	g := &mermaidGraph{
		lines: []string{"graph TD"},
	}
	g.writeBody(body, "")
	return strings.Join(g.lines, "\n") + "\n"
}

type mermaidGraph struct {
	lines   []string
	counter int
}

func (g *mermaidGraph) nextID() string {
	g.counter++
	return fmt.Sprintf("n%d", g.counter)
}

func (g *mermaidGraph) node(id, label, shape string) {
	var line string
	switch shape {
	case "round":
		line = fmt.Sprintf("    %s(%s)", id, mermaidEscape(label))
	case "stadium":
		line = fmt.Sprintf("    %s([%s])", id, mermaidEscape(label))
	case "diamond":
		line = fmt.Sprintf("    %s{%s}", id, mermaidEscape(label))
	case "hex":
		line = fmt.Sprintf("    %s{{%s}}", id, mermaidEscape(label))
	default: // rect
		line = fmt.Sprintf("    %s[%s]", id, mermaidEscape(label))
	}
	g.lines = append(g.lines, line)
}

func (g *mermaidGraph) edge(from, to, label string) {
	if label == "" {
		g.lines = append(g.lines, fmt.Sprintf("    %s --> %s", from, to))
	} else {
		g.lines = append(g.lines, fmt.Sprintf("    %s -->|%s| %s", from, mermaidEscape(label), to))
	}
}

func (g *mermaidGraph) writeBody(body Body, parentID string) string {
	id := g.nextID()
	label := fmt.Sprintf("Body (%d expr)", len(body))
	g.node(id, label, "round")
	if parentID != "" {
		g.edge(parentID, id, "")
	}
	for _, expr := range body {
		g.writeExpr(expr, id)
	}
	return id
}

func (g *mermaidGraph) writeExpr(expr *Expr, parentID string) string {
	id := g.nextID()

	label := expr.String()
	// Truncate long labels for readability.
	const maxLen = 48
	if len(label) > maxLen {
		label = label[:maxLen-1] + "…"
	}

	prefix := ""
	if expr.Negated {
		prefix = "not "
	}

	switch terms := expr.Terms.(type) {
	case *SomeDecl:
		g.node(id, prefix+"some "+terms.String(), "stadium")
		g.edge(parentID, id, fmt.Sprintf("[%d]", expr.Index))
	case *Every:
		g.node(id, prefix+everyLabel(terms), "stadium")
		g.edge(parentID, id, fmt.Sprintf("[%d]", expr.Index))
		g.writeBody(terms.Body, id)
	case []*Term:
		if len(terms) > 0 {
			op := terms[0].String()
			//g.node(id, prefix+op, "diamond")
			g.node(id, prefix+op, "round")
		} else {
			//g.node(id, prefix+"call", "diamond")
			g.node(id, prefix+"call", "round")
		}
		g.edge(parentID, id, fmt.Sprintf("[%d]", expr.Index))
		for i, t := range terms[1:] {
			g.writeTerm(t, id, fmt.Sprintf("arg%d", i))
		}
	case *Term:
		g.node(id, prefix+label, "rect")
		g.edge(parentID, id, fmt.Sprintf("[%d]", expr.Index))
	default:
		g.node(id, prefix+label, "rect")
		g.edge(parentID, id, fmt.Sprintf("[%d]", expr.Index))
	}

	for _, w := range expr.With {
		wid := g.nextID()
		g.node(wid, "with "+w.Target.String(), "hex")
		g.edge(id, wid, "")
		g.writeTerm(w.Value, wid, "value")
	}

	return id
}

func (g *mermaidGraph) writeTerm(term *Term, parentID, edgeLabel string) string {
	id := g.nextID()
	switch v := term.Value.(type) {
	case *ArrayComprehension:
		g.node(id, "[_ | ...]", "round")
		g.edge(parentID, id, edgeLabel)
		g.writeTerm(v.Term, id, "term")
		g.writeBody(v.Body, id)
	case *SetComprehension:
		g.node(id, "{_ | ...}", "round")
		g.edge(parentID, id, edgeLabel)
		g.writeTerm(v.Term, id, "term")
		g.writeBody(v.Body, id)
	case *ObjectComprehension:
		g.node(id, "{_:_ | ...}", "round")
		g.edge(parentID, id, edgeLabel)
		g.writeTerm(v.Key, id, "key")
		g.writeTerm(v.Value, id, "value")
		g.writeBody(v.Body, id)
	case *Array:
		g.node(id, fmt.Sprintf("Array(%d)", v.Len()), "round")
		g.edge(parentID, id, edgeLabel)
		for i := 0; i < v.Len(); i++ {
			g.writeTerm(v.Elem(i), id, fmt.Sprintf("%d", i))
		}
	case Call:
		op := ""
		if len(v) > 0 {
			op = v[0].String()
		}
		g.node(id, "call "+op, "round")
		g.edge(parentID, id, edgeLabel)
		for i, t := range v[1:] {
			g.writeTerm(t, id, fmt.Sprintf("arg%d", i))
		}
	default:
		label := term.String()
		const maxLen = 32
		if len(label) > maxLen {
			label = label[:maxLen-1] + "…"
		}
		g.node(id, label, "rect")
		g.edge(parentID, id, edgeLabel)
	}
	return id
}

func everyLabel(e *Every) string {
	if e.Key != nil {
		return fmt.Sprintf("every %s, %s in %s", e.Key, e.Value, e.Domain)
	}
	return fmt.Sprintf("every %s in %s", e.Value, e.Domain)
}

// mermaidEscape escapes characters that are special in Mermaid node labels.
func mermaidEscape(s string) string {
	s = strings.ReplaceAll(s, `"`, `#quot;`)
	s = strings.ReplaceAll(s, `[`, `#91;`)
	s = strings.ReplaceAll(s, `]`, `#93;`)
	s = strings.ReplaceAll(s, `(`, `#40;`)
	s = strings.ReplaceAll(s, `)`, `#41;`)
	s = strings.ReplaceAll(s, `{`, `#123;`)
	s = strings.ReplaceAll(s, `}`, `#125;`)
	return s
}
