package main

import (
	"fmt"

	"github.com/mariotoffia/gojwtlic/license/licjwt/licbuiltin"
)

func main() {
	k := licbuiltin.KeysImpl{}
	fmt.Printf("%v", k)
}
