package main

import (
	"fmt"
	"github.com/flsusp/m2mams-go-client/m2mams"
)

func main() {
	pkp := m2mams.LocalFileSystemPKProvider{}
	key, err := pkp.LoadKey("m2mams", "test2")
	panicOnError(err)
	fmt.Print(key)
}

func panicOnError(err error) {
	if err != nil {
		panic(err.Error())
	}
}