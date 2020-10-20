package kprovider

import (
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"os/user"
	"testing"
)

func TestLoadKeyFromFile(t *testing.T) {
	usr, err := user.Current()

	fs := afero.NewMemMapFs()
	pkp := LocalFileSystemKProvider{
		FileSystem: fs,
	}

	fs.MkdirAll(usr.HomeDir+"/.somecontext/your_email@example.com", 0755)
	afero.WriteFile(fs, usr.HomeDir+"/.somecontext/your_email@example.com/somekeypair", []byte(validPrivateKey), 0644)

	key, err := pkp.LoadPrivateKey("your_email@example.com", "somecontext", "somekeypair")
	assert.NoError(t, err)
	err = key.Validate()
	assert.NoError(t, err)
}

func TestLoadKeyFailsOnMissingFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	pkp := LocalFileSystemKProvider{
		FileSystem: fs,
	}

	_, err := pkp.LoadPrivateKey("your_email@example.com", "somecontext", "somekeypair")
	assert.Error(t, err)
}
