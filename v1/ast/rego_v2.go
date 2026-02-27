package ast

// CheckRegoV2 checks the given module or rule for errors that are specific to Rego v2.
// Passing something other than an *ast.Rule or *ast.Module is considered a programming error, and will cause a panic.
func CheckRegoV2(x any) Errors {
	// Rego v1 is a subset of v2
	return CheckRegoV1(x)
}
