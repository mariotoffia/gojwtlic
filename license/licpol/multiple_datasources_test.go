package licpol

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

func TestMultipleDataSources(t *testing.T) {

	// Data documents
	data1 := `{
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

	data2 := `{
	"license": {
	  "scope": "simulator regulate ui2 settings",
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

	default allow_create_a = false
	default allow_create_b = false
	
	# Only allow license scopes that the actual caller have
	# i.e. cannot add more scopes in a license request (data.json)
	# than the scopes from JWT on caller request (input.json)
	allow_create_a {
		input.method == "POST"
		input.path = ["license","generate", sawmill]
	
		iscopes := scopes_to_set(input.claims.scope)
		lscopes := scopes_to_set(data.a.license.scope)
		
		filtered := lscopes - iscopes
	
		count(filtered) == 0    
	}

	allow_create_b {
		input.method == "POST"
		input.path = ["license","generate", sawmill]
	
		iscopes := scopes_to_set(input.claims.scope)
		lscopes := scopes_to_set(data.b.license.scope)
		
		filtered := lscopes - iscopes
	
		count(filtered) == 0    
	}

	scopes_to_set(str) = {x |
	  some i
	  parts := split(str, " ")
	  x := parts[i]
	}`

	var jsonData1 map[string]interface{}
	var jsonData2 map[string]interface{}
	var jsonInput map[string]interface{}

	if err := util.UnmarshalJSON([]byte(data1), &jsonData1); err != nil {
		panic(err)
	}

	if err := util.UnmarshalJSON([]byte(data2), &jsonData2); err != nil {
		panic(err)
	}

	if err := util.UnmarshalJSON([]byte(input), &jsonInput); err != nil {
		panic(err)
	}

	// Manually create the storage layer. inmem.NewFromObject returns an
	// in-memory store containing the supplied data.
	store := inmem.New()

	ctx := context.Background()
	txn, err := store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		panic(err)
	}

	if err := store.Write(ctx, txn, storage.AddOp, storage.Path{"a"}, jsonData1); err != nil {
		panic(err)
	}

	if err := store.Write(ctx, txn, storage.AddOp, storage.Path{"b"}, jsonData2); err != nil {
		panic(err)
	}

	if err := store.Commit(ctx, txn); err != nil {
		panic(err)
	}

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err := ast.CompileModules(map[string]string{
		"licpol.testing": module,
	})

	// Create a new query that uses the compiled policy from above.
	rego := rego.New(
		rego.Query("data.example"),
		rego.Compiler(compiler),
		rego.Input(jsonInput),
		rego.Store(store),
	)

	// Run evaluation.
	rs, err := rego.Eval(ctx)

	if err != nil {
		panic(err)
	}

	jdata, err := json.Marshal(rs)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(jdata))

	// Assert results.
}
