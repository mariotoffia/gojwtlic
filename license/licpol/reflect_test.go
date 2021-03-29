package licpol

import (
	"fmt"
	"testing"
)

type MyStruct struct {
	Name   string
	Age    int
	secret string
}

func MyFunc2(ms MyStruct) string {

	v := fmt.Sprintf("%s, %d (%s)", ms.Name, ms.Age, ms.secret)
	fmt.Println(v)
	return v

}

func MyFunc(name, dir string) string {

	v := fmt.Sprintf("%s-%s", name, dir)
	fmt.Println(v)
	return v

}

func TestReflectivePrimitiveParams(t *testing.T) {

	pdp := NewPolicyEnforcementPointWithWrapper(
		map[string]PEPRegistration{
			"path/to/MyFunc": {
				Function:   MyFunc,
				Parameters: []string{"name", "dir"},
				Returns:    []string{"output"},
			},
		}, true /*createWrapper*/)

	res := pdp.Wrapper("path/to/MyFunc").(func(name, dir string) string)(
		"kalle", "kobra",
	)

	fmt.Printf("result: %s\n", res)
}

func TestReflectiveStructParam(t *testing.T) {

	pdp := NewPolicyEnforcementPointWithWrapper(
		map[string]PEPRegistration{
			"path/to/MyFunc2": {
				Function:   MyFunc2,
				Parameters: []string{"ms"},
				Returns:    []string{"output"},
			},
		}, true /*createWrapper*/)

	res := pdp.Wrapper("path/to/MyFunc2").(func(ms MyStruct) string)(
		MyStruct{
			Name:   "Nisse",
			Age:    17,
			secret: "shh"},
	)

	fmt.Printf("result: %s\n", res)
}

func BenchmarkWapInvoke(t *testing.B) {

	f := func(ms MyStruct) string { return "" }

	pdp := NewPolicyEnforcementPointWithWrapper(
		map[string]PEPRegistration{
			"path/to/MyFunc2": {
				Function:   f,
				Parameters: []string{"ms"},
				Returns:    []string{"output"},
			},
		}, true /*createWrapper*/)

	prm := MyStruct{Name: "Nisse", Age: 17, secret: "shh"}
	method := "path/to/MyFunc2"

	t.ResetTimer()

	for i := 0; i < t.N; i++ {
		pdp.Wrapper(method).(func(ms MyStruct) string)(prm)
	}
}
