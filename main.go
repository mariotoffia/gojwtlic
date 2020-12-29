package main

import (
	"fmt"

	"github.com/mariotoffia/gojwtlic/license"
)

func main() {
	k := license.KeysImpl{}
	fmt.Printf("%v", k)
}
