package m2mams_pkp

import (
	"github.com/flsusp/m2mams-go-client/m2mams"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLoadKeyFromSpecificVar(t *testing.T) {
	fakeEnv := m2mams.NewFakeEnv()
	pkp := EnvironmentVariablePKProvider{
		Environment: fakeEnv,
	}

	fakeEnv.Setenv("SOMECONTEXT-SOMEKEYPAIR-PK", validPrivateKey)

	key, err := pkp.LoadPrivateKey("somecontext", "somekeypair")
	assert.NoError(t, err)
	err = key.Validate()
	assert.NoError(t, err)
}

func TestLoadKeyFromGenericVar(t *testing.T) {
	fakeEnv := m2mams.NewFakeEnv()
	pkp := EnvironmentVariablePKProvider{
		Environment: fakeEnv,
	}

	fakeEnv.Setenv("M2MAMS-PK", validPrivateKey)

	key, err := pkp.LoadPrivateKey("somecontext", "somekeypair")
	assert.NoError(t, err)
	err = key.Validate()
	assert.NoError(t, err)
}

func TestFailsLoadingKeyIfEnvVarsNotFound(t *testing.T) {
	fakeEnv := m2mams.NewFakeEnv()
	pkp := EnvironmentVariablePKProvider{
		Environment: fakeEnv,
	}

	key, err := pkp.LoadPrivateKey("somecontext", "somekeypair")
	assert.Error(t, err)
	assert.Nil(t, key)
}

func TestLoadKeyUidFromSpecificVar(t *testing.T) {
	fakeEnv := m2mams.NewFakeEnv()
	pkp := EnvironmentVariablePKProvider{
		Environment: fakeEnv,
	}

	fakeEnv.Setenv("SOMECONTEXT-SOMEKEYPAIR-UID", "someone@example.com")

	uid, err := pkp.LoadKeyUid("somecontext", "somekeypair")
	assert.NoError(t, err)
	assert.Equal(t, "someone@example.com", uid)
}

func TestLoadKeyUidFromGenericVar(t *testing.T) {
	fakeEnv := m2mams.NewFakeEnv()
	pkp := EnvironmentVariablePKProvider{
		Environment: fakeEnv,
	}

	fakeEnv.Setenv("M2MAMS-UID", "someone@example.com")

	uid, err := pkp.LoadKeyUid("somecontext", "somekeypair")
	assert.NoError(t, err)
	assert.Equal(t, "someone@example.com", uid)
}
