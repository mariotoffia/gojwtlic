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
	GetFunction() interface{}
}

type PEPReturn interface {
	PEPInvoke
	GetReturn() []interface{}
}

// pepmsg is a struct that implements `PEPInvoke` and `PEPReturn`
//
// In this way the implementation do not need to instantiate two structs
// when invoke + return.
type pepmsg struct {
	params   []interface{}
	method   []string
	function interface{}
	ret      []interface{}
}

func (pmsg *pepmsg) GetParams() []interface{} {
	return pmsg.params
}
func (pmsg *pepmsg) GetMethod() []string {
	return pmsg.method
}
func (pmsg *pepmsg) GetFunction() interface{} {
	return pmsg.function
}
func (pmsg *pepmsg) GetReturn() []interface{} {
	return pmsg.ret
}

type PolicyEnforcementPoint interface {
	// Invoke will enforce a invocation that is about to happen
	Invoke(f interface{}, method string, prm ...interface{}) PEPInvoke
	// Return will enforce a return from a previous PEP invoke request.
	Return(invoke PEPInvoke, prm ...interface{}) PEPReturn
}

// PEPRegistration is a single entry registration for doing a PE
//
// Since go do not provide function parameter names in the metadata,
// this has to be manually created.
type PEPRegistration struct {
	Parameters []string
	Returns    []string
	Function   interface{}
	t          reflect.Type
	method     []string
}

type PEP struct {
	funcs map[string]PEPRegistration
}

// NewPolicyEnforcementPoint creates a new _PEP_ which supports the provided functions.
func NewPolicyEnforcementPoint(functions map[string]PEPRegistration) *PEP {

	pep := &PEP{
		funcs: map[string]PEPRegistration{},
	}

	for method, registration := range functions {

		rf := reflect.TypeOf(registration.Function)

		if rf.Kind() != reflect.Func {
			panic(fmt.Sprintf("expects a function, got %T for method: %s", registration, method))
		}

		registration.t = rf

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
		pep.funcs[method] = registration

	}

	return pep
}

func (pep *PEP) Invoke(f interface{}, method string, prm ...interface{}) PEPInvoke {

	registration := pep.funcs[method]

	if registration.t == nil {
		panic(fmt.Sprintf("not part of this PEP, method: %s and function:%T", method, f))
	}

	pmsg := &pepmsg{
		function: f,
		method:   registration.method,
		params:   prm,
	}

	msg := PDPMessage{
		Type:   "invoke",
		Method: pmsg.method,
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

	return pmsg
}
