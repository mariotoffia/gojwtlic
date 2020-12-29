package main

import (
	"fmt"

	"github.com/mariotoffia/gojwtlic/license/licjwt"
)

func main() {
	k := licjwt.KeysImpl{}
	fmt.Printf("%v", k)
}
