package licpol

import (
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/util"
)

// JSONInput same as input but creates a map[string]interface{} from _JSON_.
func JSONInput(json string) func(r *rego.Rego) {

	var jsonInput map[string]interface{}

	if err := util.UnmarshalJSON([]byte(json), &jsonInput); err != nil {
		panic(err)
	}

	return rego.Input(jsonInput)
}
