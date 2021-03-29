package licpol

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

type PEPInvoke interface {
	GetParams() []interface{}
	GetMethod() []string
	GetFunction() reflect.Value
}

type PEPReturn interface {
	PEPInvoke
	GetReturn() []interface{}
}

// PEPRegistration is a single entry registration for doing a PE
//
// Since go do not provide function parameter names in the metadata,
// this has to be manually created.
type PEPRegistration struct {
	Parameters []string
	Returns    []string
	Function   interface{}
	v          reflect.Value
	method     []string
	wrapper    interface{}
}

// pepmsg is a struct that implements `PEPInvoke` and `PEPReturn`
//
// In this way the implementation do not need to instantiate two structs
// when invoke + return.
type pepmsg struct {
	reg    *PEPRegistration
	params []interface{}
	ret    []interface{}
}

func (pmsg *pepmsg) GetParams() []interface{} {
	return pmsg.params
}
func (pmsg *pepmsg) GetMethod() []string {
	return pmsg.reg.method
}
func (pmsg *pepmsg) GetFunction() reflect.Value {
	return pmsg.reg.v
}
func (pmsg *pepmsg) GetReturn() []interface{} {
	return pmsg.ret
}

type PolicyEnforcementPoint interface {
	// CheckInvoke will check if it can be invoked or not.
	CheckInvoke(method string, prm ...interface{}) PEPInvoke
	// CheckReturn checks if return values is possible.
	//
	// The _invoke_ parameter is the returned parameter from `CheckInvoke`
	CheckReturn(invoke PEPInvoke, out ...interface{}) PEPReturn
	// Wrapper returns the function wrapper that will invoke the function and do
	// all PEP processing.
	//
	// CAUTION: This function uses reflection and is *much slower* than invoking
	// the function directly!
	Wrapper(method string) interface{}
}

type PEP struct {
	funcs map[string]PEPRegistration
}

// NewPolicyEnforcementPoint creates a new _PEP_ which supports the provided functions.
func NewPolicyEnforcementPoint(functions map[string]PEPRegistration) *PEP {
	return NewPolicyEnforcementPointWithWrapper(functions, false)
}

// NewPolicyEnforcementPointWithWrapper creates a new _PEP_ which supports the provided functions.
//
// If _createWrapper_ is set to `true`, it will create a function wrapper as convenience method.
func NewPolicyEnforcementPointWithWrapper(
	functions map[string]PEPRegistration,
	createWrapper bool) *PEP {

	pep := &PEP{
		funcs: map[string]PEPRegistration{},
	}

	for method, registration := range functions {

		rf := reflect.TypeOf(registration.Function)

		if rf.Kind() != reflect.Func {
			panic(fmt.Sprintf("expects a function, got %T for method: %s", registration, method))
		}

		registration.v = reflect.ValueOf(registration.Function)

		if rf.NumIn() != len(registration.Parameters) {

			panic(
				fmt.Sprintf(
					"Number of in-parameters and number of named paramters mismatch, method: %s",
					method,
				),
			)

		}

		if rf.NumOut() != len(registration.Returns) {

			panic(
				fmt.Sprintf(
					"Number of out-parameters and number of named paramters mismatch, method: %s",
					method,
				),
			)

		}

		registration.method = strings.Split(method, "/")

		if createWrapper {

			registration.wrapper = reflect.MakeFunc(rf, func(in []reflect.Value) []reflect.Value {

				prm := make([]interface{}, len(in))

				for i := range in {
					prm[i] = in[i].Interface()
				}

				result := pep.CheckInvoke(method, prm...)

				// TODO: handle rejection or filtering of parameters

				// TODO: If partial resolved policy, the function need to accept
				// TODO: PEPInvoke as second param (CbContext as first param).
				// TODO: Add ast to PEPInvoke interface for GetPartial()...

				out := registration.v.Call(in)

				// TODO: Process and - CheckReturn()
				outprm := make([]interface{}, len(out))

				for i := range out {
					outprm[i] = out[i].Interface()
				}

				/*ret := */
				pep.CheckReturn(result, outprm...)
				// TODO: Extract return arguments and return them.

				// TODO: it should return ret instead
				return out
			}).Interface()

			pep.funcs[method] = registration
		}
	}

	return pep
}

func (pep *PEP) Wrapper(method string) interface{} {

	if registration, ok := pep.funcs[method]; ok {
		return registration.wrapper
	}

	panic(fmt.Sprintf("not part of this PEP, method: %s", method))
}

// CheckInvoke will check if it can be invoked or not.
func (pep *PEP) CheckInvoke(method string, prm ...interface{}) PEPInvoke {

	registration := pep.funcs[method]

	if registration.Parameters == nil {
		panic(fmt.Sprintf("not part of this PEP, method: %s", method))
	}

	pmsg := &pepmsg{
		reg:    &registration,
		params: prm,
		ret:    nil,
	}

	msg := PDPMessage{
		Type:   "invoke",
		Method: pmsg.reg.method,
		Body:   map[string]interface{}{},
	}

	for i, name := range registration.Parameters {
		msg.Body[name] = prm[i]
	}

	json, err := json.Marshal(&msg)
	if err != nil {
		panic(err)
	}

	fmt.Println("Feeding JSON to PDP")
	fmt.Println(string(json))

	// TODO: feed to PDP and process the result into pmsg

	return pmsg

}

func (pep *PEP) CheckReturn(invoke PEPInvoke, out ...interface{}) PEPReturn {
	// TODO: Implement me!
	return invoke.(*pepmsg)
}
