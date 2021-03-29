package licpol

import (
	"fmt"
	"reflect"
	"strconv"
)

// PDPMessage is a standar PDP message.
//
// .Example Invocation
// [source,json]
// ----
// {
//   "type": "invoke", // <1>
//   "method": ["path","to","method-name"], // <2>
//   "sc": {
//     "oidc": { // <3>
//         "aud": "https://nordvestor.api.crossbreed.se",
//         "iss": "https://iss.crossbreed.se",
//         "sub": "hobbe.nisse@azcam.net",
//         "exp": 1927735782,
//         "iat": 1612375782,
//         "nbf": 1612375782,
//         "jti": "fcd2174b-664a-11eb-afe1-1629c910062f",
//         "client_id": "my-client-id",
//         "scope": "oid::r::999 oid::rw::1234"
//     }
//   },
//   "body": { // <4>
//     "name": "my-param",
//     "dir": "inbound"
//   }
// }
// ----
// <1> About to invoke function
// <2> The action, i.e. path to method
// <3> The security context, in this case the _OpenID Connect_ token
// <4> Body do contain the function parameters marshalled to _JSON_
type PDPMessage struct {
	Type            string                 `json:"type"`
	Method          []string               `json:"method"`
	SecurityContext map[string]interface{} `json:"sc,omitempty"`
	Body            map[string]interface{} `json:"body,omitempty"`
}

// PDP is the Policy Decision Point implementation
type PDP struct {
}

func (pdp *PDP) Register(f interface{}) {

	rf := reflect.TypeOf(f)

	if rf.Kind() != reflect.Func {
		panic("expects a function")
	}

	numIn := rf.NumIn()   //Count inbound parameters
	numOut := rf.NumOut() //Count outbounding parameters

	fmt.Println("Method:", rf.String())
	fmt.Println("Variadic:", rf.IsVariadic()) // Used (<type> ...) ?
	fmt.Println("Package:", rf.PkgPath())

	for i := 0; i < numIn; i++ {

		inV := rf.In(i)
		in_Kind := inV.Kind()
		fmt.Println(inV)
		fmt.Printf("\nParameter IN: "+strconv.Itoa(i)+"\nKind: %v\nName: %v\n-----------", in_Kind, inV.Name())
	}
	for o := 0; o < numOut; o++ {

		returnV := rf.Out(0)
		return_Kind := returnV.Kind()
		fmt.Printf("\nParameter OUT: "+strconv.Itoa(o)+"\nKind: %v\nName: %v\n", return_Kind, returnV.Name())
	}

}
