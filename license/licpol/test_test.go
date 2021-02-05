package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
	"github.com/stretchr/testify/assert"
)

func TestError(t *testing.T) {

	ctx := context.Background()

	// Data document
	data := `{
		"skip": ["IDT", "IDT_"],
		"report": ["ODT"],
		"fail": ["RHCS", "RHCS_"],
		"range": {
			"IDT": [-100, 100],
			"IDT_": [-100, 100],
			"RHCS": [20, 200],
			"RHCS_": [20, 200]
		}
}`

	// Input document
	input := `{
		"generate": {
			"IDT": 22,
			"IDT_C1_O2": -656,
			"IDT_C1_O3": 19.2,
			"IDT_C1_O1": 22.2
		},
		"target": {
			"IDT": 22,
			"IDT_C1_O2": -656,
			"IDT_C1_O3": "$error",
			"ODT": "$error",
			"IDT_C1_O1": 22.2
		},
		"target-errors": {
			"IDT_C1_O3": "the error message",
			"ODT": "the error message"
		}
}`

	// Policy document
	module := `package cbprovider

	error_dp[dp] {
		my := input.target[dp]
		my == "$error"		
	}`

	var jsonData map[string]interface{}
	var jsonInput map[string]interface{}

	if err := util.UnmarshalJSON([]byte(data), &jsonData); err != nil {
		panic(err)
	}

	if err := util.UnmarshalJSON([]byte(input), &jsonInput); err != nil {
		panic(err)
	}

	// Manually create the storage layer. inmem.NewFromObject returns an
	// in-memory store containing the supplied data.
	store := inmem.NewFromObject(jsonData)

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err := ast.CompileModules(map[string]string{
		"cbprovider": module,
	})

	// Create a new query that uses the compiled policy from above.
	rego := rego.New(
		rego.Query("data.cbprovider.error_dp"),
		rego.Compiler(compiler),
		rego.Input(jsonInput),
		rego.Store(store),
	)

	// Run evaluation.
	rs, err := rego.Eval(ctx)

	if err != nil {
		panic(err)
	}

	result, err := json.Marshal(rs)

	if err != nil {
		panic(err)
	}

	fmt.Println(string(result))
}

func TestLicenseScopeOk(t *testing.T) {

	ctx := context.Background()

	// Data document
	data := `{
  "license": {
    "scope": "simulator regulate ui settings",
    "features": {
      "settings": {
        "claims": {
          "access": "rw",
          "ai": true,
          "ao": true,
          "di": true,
          "do": true
        }
      }
    }
  }
}`

	// Input document
	input := `{
  "method": "POST",
  "claims": {
    "aud": "https://api.valmatics.se",
    "iss": "https://api.valmatics.se/licmgr",
    "sub": "hobbe.nisse@azcam.net",
    "exp": 1927735782,
    "iat": 1612375782,
    "nbf": 1612375782,
    "jti": "fcd2174b-664a-11eb-afe1-1629c910062f",
    "client_id": "valmatics2.x",
    "client_secret": "SecretFromAWSCognito",
    "scope": "simulator regulate ui settings master-of-puppets"
  },
  "path": ["license", "generate", "Kåge"]
}`

	// Policy document
	module := `
	package example

	default allow_create = false
	
	# Only allow license scopes that the actual caller have
	# i.e. cannot add more scopes in a license request (data.json)
	# than the scopes from JWT on caller request (input.json)
	allow_create {
		input.method == "POST"
		input.path = ["license","generate", sawmill]
	
		iscopes := scopes_to_set(input.claims.scope)
		lscopes := scopes_to_set(data.license.scope)
		
		filtered := lscopes - iscopes
	
		count(filtered) == 0    
	}
	
	scopes_to_set(str) = {x |
	  some i
	  parts := split(str, " ")
	  x := parts[i]
	}`

	var jsonData map[string]interface{}
	var jsonInput map[string]interface{}

	if err := util.UnmarshalJSON([]byte(data), &jsonData); err != nil {
		panic(err)
	}

	if err := util.UnmarshalJSON([]byte(input), &jsonInput); err != nil {
		panic(err)
	}

	// Manually create the storage layer. inmem.NewFromObject returns an
	// in-memory store containing the supplied data.
	store := inmem.NewFromObject(jsonData)

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err := ast.CompileModules(map[string]string{
		"licpol.testing": module,
	})

	// Create a new query that uses the compiled policy from above.
	rego := rego.New(
		rego.Query("data.example.allow_create"),
		rego.Compiler(compiler),
		rego.Input(jsonInput),
		rego.Store(store),
	)

	// Run evaluation.
	rs, err := rego.Eval(ctx)

	if err != nil {
		panic(err)
	}

	// Assert results.
	assert.Equal(t, 1, len(rs))
	assert.Equal(t, "data.example.allow_create", rs[0].Expressions[0].Text)
	assert.Equal(t, true, rs[0].Expressions[0].Value)
}

func TestLicenseScopeTooFew(t *testing.T) {

	ctx := context.Background()

	// Data document
	data := `{
  "license": {
    "scope": "simulator regulate ui settings",
    "features": {
      "settings": {
        "claims": {
          "access": "rw",
          "ai": true,
          "ao": true,
          "di": true,
          "do": true
        }
      }
    }
  }
}`
	// Input document
	input := `{
  "method": "POST",
  "claims": {"scope": "simulator regulate settings master-of-puppets"},
  "path": ["license", "generate", "Kåge"]
}`

	// Policy document
	module := `
	package example

	default allow_create = false
	
	# Only allow license scopes that the actual caller have
	# i.e. cannot add more scopes in a license request (data.json)
	# than the scopes from JWT on caller request (input.json)
	allow_create {
		input.method == "POST"
		input.path = ["license","generate", sawmill]
	
		iscopes := scopes_to_set(input.claims.scope)
		lscopes := scopes_to_set(data.license.scope)
		
		filtered := lscopes - iscopes
	
		count(filtered) == 0    
	}
	
	scopes_to_set(str) = {x |
	  some i
	  parts := split(str, " ")
	  x := parts[i]
	}`

	var jsonData map[string]interface{}
	var jsonInput map[string]interface{}

	if err := util.UnmarshalJSON([]byte(data), &jsonData); err != nil {
		panic(err)
	}

	if err := util.UnmarshalJSON([]byte(input), &jsonInput); err != nil {
		panic(err)
	}

	// Manually create the storage layer. inmem.NewFromObject returns an
	// in-memory store containing the supplied data.
	store := inmem.NewFromObject(jsonData)

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err := ast.CompileModules(map[string]string{
		"licpol.testing": module,
	})

	// Create a new query that uses the compiled policy from above.
	rego := rego.New(
		rego.Query("data.example.allow_create"),
		rego.Compiler(compiler),
		rego.Input(jsonInput),
		rego.Store(store),
	)

	// Run evaluation.
	rs, err := rego.Eval(ctx)

	if err != nil {
		panic(err)
	}

	// Assert results.
	assert.Equal(t, 1, len(rs))

	expr := rs[0].Expressions[0]
	assert.Equal(t, "data.example.allow_create", expr.Text)
	assert.Equal(t, false, expr.Value)
}

func BenchmarkLicenseScopeOk(t *testing.B) {

	ctx := context.Background()

	// Data document
	data := `{
  "license": {
    "scopes": "simulator regulate ui settings",
    "features": {
      "settings": {
        "claims": {
          "access": "rw",
          "ai": true,
          "ao": true,
          "di": true,
          "do": true
        }
      }
    }
  }
}`
	// Input document
	input := `{
  "method": "POST",
  "claims": {"scopes": "simulator regulate ui settings master-of-puppets"},
  "path": ["license", "generate", "Kåge"]
}`

	// Policy document
	module := `
	package example

	default allow_create = false
	
	# Only allow license scopes that the actual caller have
	# i.e. cannot add more scopes in a license request (data.json)
	# than the scopes from JWT on caller request (input.json)
	allow_create {
		input.method == "POST"
		input.path = ["license","generate", sawmill]
	
		iscopes := scopes_to_set(input.claims.scopes)
		lscopes := scopes_to_set(data.license.scopes)
		
		filtered := lscopes - iscopes
	
		count(filtered) == 0    
	}
	
	scopes_to_set(str) = {x |
	  some i
	  parts := split(str, " ")
	  x := parts[i]
	}`

	var jsonData map[string]interface{}
	var jsonInput map[string]interface{}

	if err := util.UnmarshalJSON([]byte(data), &jsonData); err != nil {
		panic(err)
	}

	if err := util.UnmarshalJSON([]byte(input), &jsonInput); err != nil {
		panic(err)
	}

	// Manually create the storage layer. inmem.NewFromObject returns an
	// in-memory store containing the supplied data.
	store := inmem.NewFromObject(jsonData)

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err := ast.CompileModules(map[string]string{
		"licpol.testing": module,
	})

	if err != nil {
		panic(err)
	}

	t.ResetTimer()

	for i := 0; i < t.N; i++ {
		// Create a new query that uses the compiled policy from above.
		rego := rego.New(
			rego.Query("data.example.allow_create"),
			rego.Compiler(compiler),
			rego.Input(jsonInput),
			rego.Store(store),
		)

		// Run evaluation.
		_, err := rego.Eval(ctx)

		if err != nil {
			panic(err)
		}

	}
}

func BenchmarkLicenseScopeTooFew(t *testing.B) {

	ctx := context.Background()

	// Data document
	data := `{
  "license": {
    "scopes": "simulator regulate ui settings",
    "features": {
      "settings": {
        "claims": {
          "access": "rw",
          "ai": true,
          "ao": true,
          "di": true,
          "do": true
        }
      }
    }
  }
}`
	// Input document
	input := `{
  "method": "POST",
  "claims": {"scopes": "simulator regulate settings master-of-puppets"},
  "path": ["license", "generate", "Kåge"]
}`

	// Policy document
	module := `
	package example

	default allow_create = false
	
	# Only allow license scopes that the actual caller have
	# i.e. cannot add more scopes in a license request (data.json)
	# than the scopes from JWT on caller request (input.json)
	allow_create {
		input.method == "POST"
		input.path = ["license","generate", sawmill]
	
		iscopes := scopes_to_set(input.claims.scopes)
		lscopes := scopes_to_set(data.license.scopes)
		
		filtered := lscopes - iscopes
	
		count(filtered) == 0    
	}
	
	scopes_to_set(str) = {x |
	  some i
	  parts := split(str, " ")
	  x := parts[i]
	}`

	var jsonData map[string]interface{}
	var jsonInput map[string]interface{}

	if err := util.UnmarshalJSON([]byte(data), &jsonData); err != nil {
		panic(err)
	}

	if err := util.UnmarshalJSON([]byte(input), &jsonInput); err != nil {
		panic(err)
	}

	// Manually create the storage layer. inmem.NewFromObject returns an
	// in-memory store containing the supplied data.
	store := inmem.NewFromObject(jsonData)

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err := ast.CompileModules(map[string]string{
		"licpol.testing": module,
	})

	if err != nil {
		panic(err)
	}

	t.ResetTimer()

	for i := 0; i < t.N; i++ {
		// Create a new query that uses the compiled policy from above.
		rego := rego.New(
			rego.Query("data.example.allow_create"),
			rego.Compiler(compiler),
			rego.Input(jsonInput),
			rego.Store(store),
		)

		// Run evaluation.
		_, err := rego.Eval(ctx)

		if err != nil {
			panic(err)
		}

	}
}
