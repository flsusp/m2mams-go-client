package m2mams_pkp

import (
	"github.com/flsusp/m2mams-go-client/m2mams"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLoadKeyFromSpecificVar(t *testing.T) {
	fakeEnv := m2mams.NewFakeEnv()
	pkp := EnvironmentVariablePKProvider{
		environment: fakeEnv,
	}

	fakeEnv.Setenv("SOMECONTEXT-SOMEKEYPAIR-PK", validPrivateKey)

	key, err := pkp.LoadKey("somecontext", "somekeypair")
	assert.NoError(t, err)
	err = key.Validate()
	assert.NoError(t, err)
}

func TestLoadKeyFromGenericVar(t *testing.T) {
	fakeEnv := m2mams.NewFakeEnv()
	pkp := EnvironmentVariablePKProvider{
		environment: fakeEnv,
	}

	fakeEnv.Setenv("M2MAMS-PK", validPrivateKey)

	key, err := pkp.LoadKey("somecontext", "somekeypair")
	assert.NoError(t, err)
	err = key.Validate()
	assert.NoError(t, err)
}

func TestFailsLoadingKeyIfEnvVarsNotFound(t *testing.T) {
	fakeEnv := m2mams.NewFakeEnv()
	pkp := EnvironmentVariablePKProvider{
		environment: fakeEnv,
	}

	key, err := pkp.LoadKey("somecontext", "somekeypair")
	assert.Error(t, err)
	assert.Nil(t, key)
}

