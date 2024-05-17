// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	iStrs "github.com/open-policy-agent/opa/internal/strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

const (
	minLocationWidth      = 5 // len("query")
	maxIdealLocationWidth = 64
	locationPadding       = 4
)

// Op defines the types of tracing events.
type Op string

const (
	// EnterOp is emitted when a new query is about to be evaluated.
	EnterOp Op = "Enter"

	// ExitOp is emitted when a query has evaluated to true.
	ExitOp Op = "Exit"

	// EvalOp is emitted when an expression is about to be evaluated.
	EvalOp Op = "Eval"

	// RedoOp is emitted when an expression, rule, or query is being re-evaluated.
	RedoOp Op = "Redo"

	// SaveOp is emitted when an expression is saved instead of evaluated
	// during partial evaluation.
	SaveOp Op = "Save"

	// FailOp is emitted when an expression evaluates to false.
	FailOp Op = "Fail"

	// DuplicateOp is emitted when a query has produced a duplicate value. The search
	// will stop at the point where the duplicate was emitted and backtrack.
	DuplicateOp Op = "Duplicate"

	// NoteOp is emitted when an expression invokes a tracing built-in function.
	NoteOp Op = "Note"

	// IndexOp is emitted during an expression evaluation to represent lookup
	// matches.
	IndexOp Op = "Index"

	// WasmOp is emitted when resolving a ref using an external
	// Resolver.
	WasmOp Op = "Wasm"

	// UnifyOp is emitted when two terms are unified.  Node will be set to an
	// equality expression with the two terms.  This Node will not have location
	// info.
	UnifyOp           Op = "Unify"
	FailedAssertionOp Op = "FailedAssertion"
)

// VarMetadata provides some user facing information about
// a variable in some policy.
type VarMetadata struct {
	Name     ast.Var       `json:"name"`
	Location *ast.Location `json:"location"`
}

// Event contains state associated with a tracing event.
type Event struct {
	Op            Op                      // Identifies type of event.
	Node          ast.Node                // Contains AST node relevant to the event.
	Location      *ast.Location           // The location of the Node this event relates to.
	QueryID       uint64                  // Identifies the query this event belongs to.
	ParentID      uint64                  // Identifies the parent query this event belongs to.
	Locals        *ast.ValueMap           // Contains local variable bindings from the query context. Nil if variables were not included in the trace event.
	LocalMetadata map[ast.Var]VarMetadata // Contains metadata for the local variable bindings. Nil if variables were not included in the trace event.
	Message       string                  // Contains message for Note events.
	Ref           *ast.Ref                // Identifies the subject ref for the event. Only applies to Index and Wasm operations.

	input    *ast.Term
	bindings *bindings
}

// HasRule returns true if the Event contains an ast.Rule.
func (evt *Event) HasRule() bool {
	_, ok := evt.Node.(*ast.Rule)
	return ok
}

// HasBody returns true if the Event contains an ast.Body.
func (evt *Event) HasBody() bool {
	_, ok := evt.Node.(ast.Body)
	return ok
}

// HasExpr returns true if the Event contains an ast.Expr.
func (evt *Event) HasExpr() bool {
	_, ok := evt.Node.(*ast.Expr)
	return ok
}

// Equal returns true if this event is equal to the other event.
func (evt *Event) Equal(other *Event) bool {
	if evt.Op != other.Op {
		return false
	}
	if evt.QueryID != other.QueryID {
		return false
	}
	if evt.ParentID != other.ParentID {
		return false
	}
	if !evt.equalNodes(other) {
		return false
	}
	return evt.Locals.Equal(other.Locals)
}

func (evt *Event) String() string {
	return fmt.Sprintf("%v %v %v (qid=%v, pqid=%v)", evt.Op, evt.Node, evt.Locals, evt.QueryID, evt.ParentID)
}

// Input returns the input object as it was at the event.
func (evt *Event) Input() *ast.Term {
	return evt.input
}

// Plug plugs event bindings into the provided ast.Term. Because bindings are mutable, this only makes sense to do when
// the event is emitted rather than on recorded trace events as the bindings are going to be different by then.
func (evt *Event) Plug(term *ast.Term) *ast.Term {
	return evt.bindings.Plug(term)
}

func (evt *Event) equalNodes(other *Event) bool {
	switch a := evt.Node.(type) {
	case ast.Body:
		if b, ok := other.Node.(ast.Body); ok {
			return a.Equal(b)
		}
	case *ast.Rule:
		if b, ok := other.Node.(*ast.Rule); ok {
			return a.Equal(b)
		}
	case *ast.Expr:
		if b, ok := other.Node.(*ast.Expr); ok {
			return a.Equal(b)
		}
	case nil:
		return other.Node == nil
	}
	return false
}

// Tracer defines the interface for tracing in the top-down evaluation engine.
// Deprecated: Use QueryTracer instead.
type Tracer interface {
	Enabled() bool
	Trace(*Event)
}

// QueryTracer defines the interface for tracing in the top-down evaluation engine.
// The implementation can provide additional configuration to modify the tracing
// behavior for query evaluations.
type QueryTracer interface {
	Enabled() bool
	TraceEvent(Event)
	Config() TraceConfig
}

// TraceConfig defines some common configuration for Tracer implementations
type TraceConfig struct {
	PlugLocalVars bool // Indicate whether to plug local variable bindings before calling into the tracer.
}

// legacyTracer Implements the QueryTracer interface by wrapping an older Tracer instance.
type legacyTracer struct {
	t Tracer
}

func (l *legacyTracer) Enabled() bool {
	return l.t.Enabled()
}

func (l *legacyTracer) Config() TraceConfig {
	return TraceConfig{
		PlugLocalVars: true, // For backwards compatibility old tracers will plug local variables
	}
}

func (l *legacyTracer) TraceEvent(evt Event) {
	l.t.Trace(&evt)
}

// WrapLegacyTracer will create a new QueryTracer which wraps an
// older Tracer instance.
func WrapLegacyTracer(tracer Tracer) QueryTracer {
	return &legacyTracer{t: tracer}
}

// BufferTracer implements the Tracer and QueryTracer interface by
// simply buffering all events received.
type BufferTracer []*Event

// NewBufferTracer returns a new BufferTracer.
func NewBufferTracer() *BufferTracer {
	return &BufferTracer{}
}

// Enabled always returns true if the BufferTracer is instantiated.
func (b *BufferTracer) Enabled() bool {
	return b != nil
}

// Trace adds the event to the buffer.
// Deprecated: Use TraceEvent instead.
func (b *BufferTracer) Trace(evt *Event) {
	*b = append(*b, evt)
}

// TraceEvent adds the event to the buffer.
func (b *BufferTracer) TraceEvent(evt Event) {
	*b = append(*b, &evt)
}

// Config returns the Tracers standard configuration
func (b *BufferTracer) Config() TraceConfig {
	return TraceConfig{PlugLocalVars: true}
}

// PrettyTrace pretty prints the trace to the writer.
func PrettyTrace(w io.Writer, trace []*Event) {
	PrettyTraceWithOpts(w, trace, TraceOptions{})
}

// PrettyTraceWithLocation prints the trace to the writer and includes location information
func PrettyTraceWithLocation(w io.Writer, trace []*Event) {
	PrettyTraceWithOpts(w, trace, TraceOptions{Locations: true})
}

type TraceOptions struct {
	Locations      bool
	ExprVariables  bool
	LocalVariables bool
	//LocationVars   bool
}

func PrettyTraceWithOpts(w io.Writer, trace []*Event, opts TraceOptions) {
	depths := depths{}

	filePathAliases, longest := getShortenedFileNames(trace)

	// Always include some padding between the trace and location
	locationWidth := longest + locationPadding

	for _, event := range trace {
		depth := depths.GetOrSet(event.QueryID, event.ParentID)
		if opts.Locations {
			location := formatLocation(event, filePathAliases)
			_, _ = fmt.Fprintf(w, "%-*s ", locationWidth, location)
		}
		_, _ = fmt.Fprint(w, formatEvent(event, depth))
		if opts.LocalVariables {
			_, _ = fmt.Fprintf(w, " %v", event.Locals)
		}
		if opts.ExprVariables {
			vars := ast.NewValueMap()
			ast.WalkTerms(event.Node, func(term *ast.Term) bool {
				// We walk the terms in the evaluated node
				if term.Location == nil {
					return false
				}
				if v, ok := term.Value.(ast.Var); ok {
					meta, ok := event.LocalMetadata[v]
					if !ok {
						return false
					}
					val := event.Locals.Get(v)
					vars.Put(meta.Name, val)
				}
				return false
			})
			_, _ = fmt.Fprintf(w, " %v", vars)
		}
		_, _ = fmt.Fprintln(w)
	}
}

func formatEvent(event *Event, depth int) string {
	padding := formatEventPadding(event, depth)
	if event.Op == NoteOp {
		return fmt.Sprintf("%v%v %q", padding, event.Op, event.Message)
	}

	var details interface{}
	if node, ok := event.Node.(*ast.Rule); ok {
		details = node.Path()
	} else if event.Ref != nil {
		details = event.Ref
	} else {
		details = rewrite(event).Node
	}

	template := "%v%v %v"
	opts := []interface{}{padding, event.Op, details}

	if event.Message != "" {
		template += " %v"
		opts = append(opts, event.Message)
	}

	return fmt.Sprintf(template, opts...)
}

func formatEventPadding(event *Event, depth int) string {
	spaces := formatEventSpaces(event, depth)
	if spaces > 1 {
		return strings.Repeat("| ", spaces-1)
	}
	return ""
}

func formatEventSpaces(event *Event, depth int) int {
	switch event.Op {
	case EnterOp:
		return depth
	case RedoOp:
		if _, ok := event.Node.(*ast.Expr); !ok {
			return depth
		}
	}
	return depth + 1
}

// getShortenedFileNames will return a map of file paths to shortened aliases
// that were found in the trace. It also returns the longest location expected
func getShortenedFileNames(trace []*Event) (map[string]string, int) {
	// Get a deduplicated list of all file paths
	// and the longest file path size
	fpAliases := map[string]string{}
	var canShorten []string
	longestLocation := 0
	for _, event := range trace {
		if event.Location != nil {
			if event.Location.File != "" {
				// length of "<name>:<row>"
				curLen := len(event.Location.File) + numDigits10(event.Location.Row) + 1
				if curLen > longestLocation {
					longestLocation = curLen
				}

				if _, ok := fpAliases[event.Location.File]; ok {
					continue
				}

				canShorten = append(canShorten, event.Location.File)

				// Default to just alias their full path
				fpAliases[event.Location.File] = event.Location.File
			} else {
				// length of "<min width>:<row>"
				curLen := minLocationWidth + numDigits10(event.Location.Row) + 1
				if curLen > longestLocation {
					longestLocation = curLen
				}
			}
		}
	}

	if len(canShorten) > 0 && longestLocation > maxIdealLocationWidth {
		fpAliases, longestLocation = iStrs.TruncateFilePaths(maxIdealLocationWidth, longestLocation, canShorten...)
	}

	return fpAliases, longestLocation
}

func numDigits10(n int) int {
	if n < 10 {
		return 1
	}
	return numDigits10(n/10) + 1
}

func formatLocation(event *Event, fileAliases map[string]string) string {

	location := event.Location
	if location == nil {
		return ""
	}

	if location.File == "" {
		return fmt.Sprintf("query:%v", location.Row)
	}

	return fmt.Sprintf("%v:%v", fileAliases[location.File], location.Row)
}

// depths is a helper for computing the depth of an event. Events within the
// same query all have the same depth. The depth of query is
// depth(parent(query))+1.
type depths map[uint64]int

func (ds depths) GetOrSet(qid uint64, pqid uint64) int {
	depth := ds[qid]
	if depth == 0 {
		depth = ds[pqid]
		depth++
		ds[qid] = depth
	}
	return depth
}

func builtinTrace(bctx BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {

	str, err := builtins.StringOperand(operands[0].Value, 1)
	if err != nil {
		return handleBuiltinErr(ast.Trace.Name, bctx.Location, err)
	}

	if !bctx.TraceEnabled {
		return iter(ast.BooleanTerm(true))
	}

	evt := Event{
		Op:       NoteOp,
		Location: bctx.Location,
		QueryID:  bctx.QueryID,
		ParentID: bctx.ParentID,
		Message:  string(str),
	}

	for i := range bctx.QueryTracers {
		bctx.QueryTracers[i].TraceEvent(evt)
	}

	return iter(ast.BooleanTerm(true))
}

func rewrite(event *Event) *Event {

	cpy := *event

	var node ast.Node

	switch v := event.Node.(type) {
	case *ast.Expr:
		expr := v.Copy()

		// Hide generated local vars in 'key' position that have not been
		// rewritten.
		if ev, ok := v.Terms.(*ast.Every); ok {
			if kv, ok := ev.Key.Value.(ast.Var); ok {
				if rw, ok := cpy.LocalMetadata[kv]; !ok || rw.Name.IsGenerated() {
					expr.Terms.(*ast.Every).Key = nil
				}
			}
		}
		node = expr
	case ast.Body:
		node = v.Copy()
	case *ast.Rule:
		node = v.Copy()
	}

	_, _ = ast.TransformVars(node, func(v ast.Var) (ast.Value, error) {
		if meta, ok := cpy.LocalMetadata[v]; ok {
			return meta.Name, nil
		}
		return v, nil
	})

	cpy.Node = node

	return &cpy
}

type varInfo struct {
	VarMetadata
	val     ast.Value
	exprLoc *ast.Location
	col     int
}

func (v varInfo) Value() string {
	if v.val != nil {
		return v.val.String()
	}
	return "undefined"
}

func trimLocationText(loc *ast.Location) string {
	if loc == nil {
		return ""
	}

	text := string(loc.Text)
	if loc.Col == 0 {
		return text
	}

	buf := new(bytes.Buffer)
	for i, line := range strings.Split(text, "\n") {
		if i == 0 {
			buf.WriteString(line)
		} else {
			buf.WriteString("\n")
			buf.WriteString(line[loc.Col-1:])
		}
	}
	return buf.String()
}

type PrettyExprOpts struct {
	Prefix string
}

func PrettyExprWithVars(e *Event, opts PrettyExprOpts) string {
	buf := new(bytes.Buffer)
	buf.WriteString(opts.Prefix)
	buf.WriteString(trimLocationText(e.Location))
	buf.WriteString("\n")

	if e.Location == nil {
		return buf.String()
	}

	expr, err := ast.ParseExpr(string(e.Location.Text))
	if err != nil {
		return buf.String()
	}

	exprVars := map[string]varInfo{}
	exprCol := e.Location.Col

	ast.WalkTerms(expr, func(term *ast.Term) bool {
		if term.Location == nil {
			return false
		}
		if v, ok := term.Value.(ast.Var); ok {
			localV, meta, ok := reverseLookupInMeta(e.LocalMetadata, v)
			if !ok {
				return false
			}
			info := varInfo{
				VarMetadata: meta,
				val:         e.Locals.Get(localV),
				exprLoc:     term.Location,
			}
			if term.Location != nil {
				if term.Location.Row != expr.Location.Row {
					info.col = term.Location.Col - exprCol
				} else {
					info.col = term.Location.Col - 1
				}
			}
			exprVars[string(v)] = info
		}
		return false
	})

	printVarArrows(buf, exprVars, opts.Prefix)
	return buf.String()
}

func reverseLookupInMeta(meta map[ast.Var]VarMetadata, v ast.Var) (ast.Var, VarMetadata, bool) {
	for k, m := range meta {
		if m.Name == v {
			return k, m, true
		}
	}
	return "", VarMetadata{}, false
}

func printVarArrows(w *bytes.Buffer, exprVars map[string]varInfo, prefix string) {
	byCol := make([]varInfo, 0, len(exprVars))
	for _, info := range exprVars {
		byCol = append(byCol, info)
	}
	sort.Slice(byCol, func(i, j int) bool {
		return byCol[i].col < byCol[j].col
	})

	w.WriteString(prefix)
	printArrows(w, byCol, -1)
	for i := len(byCol) - 1; i >= 0; i-- {
		w.WriteString(prefix)
		printArrows(w, byCol, i)
	}
}

func printArrows(w *bytes.Buffer, l []varInfo, printValueAt int) {
	prevCol := 0
	var slice []varInfo
	if printValueAt >= 0 {
		slice = l[:printValueAt+1]
	} else {
		slice = l
	}
	for i, info := range slice {

		isLast := i >= len(slice)-1
		col := info.col

		if !isLast && col == l[i+1].col {
			continue
		}

		spaces := col
		if i > 0 {
			spaces = (col - prevCol) - 1
		}

		if spaces > 0 {
			w.WriteString(strings.Repeat(" ", spaces))
		}

		if isLast && printValueAt >= 0 {
			if (i > 0 && col == l[i-1].col) || (i < len(l)-1 && col == l[i+1].col) {
				w.WriteString(fmt.Sprintf("%s: %s", info.Name, info.Value()))
			} else {
				w.WriteString(info.Value())
			}
		} else {
			w.WriteString("|")
		}
		prevCol = col
	}
	w.WriteString("\n")
}

func init() {
	RegisterBuiltinFunc(ast.Trace.Name, builtinTrace)
}
