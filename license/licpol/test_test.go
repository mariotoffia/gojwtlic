package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

func TestOpa1(t *testing.T) {

	ctx := context.Background()

	// Define a simple policy.
	module := `
		package example
		default allow = false
		allow {
			input.identity = "admin"
		}
		allow {
			input.method = "GET"
		}
	`

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err := ast.CompileModules(map[string]string{
		"example.rego": module,
	})

	// Create a new query that uses the compiled policy from above.
	rego := rego.New(
		rego.Query("data.example.allow"),
		rego.Compiler(compiler),
		rego.Input(
			map[string]interface{}{
				"identity": "bob",
				"method":   "GET",
			},
		),
	)

	// Run evaluation.
	rs, err := rego.Eval(ctx)

	if err != nil {
		// Handle error.
	}

	// Inspect results.
	fmt.Println("len:", len(rs))
	fmt.Println("value:", rs[0].Expressions[0].Value)

	// Output:
	//
	// len: 1
	// value: true
}
