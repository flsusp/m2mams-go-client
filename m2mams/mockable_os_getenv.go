package m2mams

import (
	"os"
)

type Environment interface {
	Getenv(key string) string
}

func (OsEnv) Getenv(key string) string {
	return os.Getenv(key)
}

type OsEnv struct{}

func (f FakeEnv) Getenv(key string) string {
	return f.values[key]
}

func NewFakeEnv() FakeEnv {
	f := FakeEnv{}
	f.values = make(map[string]string)
	return f
}

func (f FakeEnv) Setenv(key string, value string) {
	f.values[key] = value
}

type FakeEnv struct {
	values map[string]string
}
