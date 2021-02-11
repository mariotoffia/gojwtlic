package licpol

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/open-policy-agent/opa/rego"
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

	pctx := New().
		RegisterModule("licpol.testing", module).
		CompileModuleSet("test-module", "licpol.testing")

	rs, err := pctx.NewEval(
		rego.Query("[data.example.allow_create_a,data.example.allow_create_b]"),
		rego.Compiler(pctx.Policy("test-module")),
		JSONInput(input),
		rego.Store(
			NewInMemStoreBuilder(
				context.Background()).
				AddJSON("a", data1).
				AddJSON("b", data2).
				Build(),
		),
	).
		Eval(context.Background())

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

func BenchmarkMultipleDataSources(t *testing.B) {

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

	pctx := New().
		RegisterModules(map[string]string{
			"licpol.testing": module,
		}).
		CompileModuleSet("test-module", "licpol.testing")

	store := NewInMemStoreBuilder(
		context.Background()).
		AddJSON("a", data1).
		AddJSON("b", data2).
		Build()

	t.ResetTimer()

	for i := 0; i < t.N; i++ {

		_, err := pctx.NewEval(
			rego.Query("[data.example.allow_create_a,data.example.allow_create_b]"),
			rego.Compiler(pctx.Policy("test-module")),
			JSONInput(input),
			rego.Store(store),
		).
			Eval(context.Background())

		if err != nil {
			panic(err)
		}
	}

}
