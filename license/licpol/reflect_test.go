package licpol

import (
	"fmt"
	"testing"
)

func MyFunc(name, dir string) string {
	return fmt.Sprintf("%s-%s", name, dir)
}

func TestReflectiveParamsExtraction(t *testing.T) {

	pdp := NewPolicyEnforcementPoint(
		map[string]PEPRegistration{
			"path/to/MyFunc": {
				Function:   MyFunc,
				Parameters: []string{"name", "dir"},
				Returns:    []string{"output"},
			},
		})

	res := pdp.Invoke(MyFunc, "path/to/MyFunc", "hello", "world")

	fmt.Println(res)
}
