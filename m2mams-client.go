package main

import (
	"fmt"
	pkp2 "github.com/flsusp/m2mams-go-client/m2mams/pkp"
)

func main() {
	pkp := pkp2.LocalFileSystemPKProvider{}
	key, err := pkp.LoadKey("m2mams", "test2")
	panicOnError(err)
	fmt.Print(key)
}

func panicOnError(err error) {
	if err != nil {
		panic(err.Error())
	}
}