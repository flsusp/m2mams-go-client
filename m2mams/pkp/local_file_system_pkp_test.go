package m2mams_pkp

import (
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"os/user"
	"testing"
)

func TestLoadKeyFromFile(t *testing.T) {
	usr, err := user.Current()

	fs := afero.NewMemMapFs()
	pkp := LocalFileSystemPKProvider{
		fileSystem: fs,
	}

	fs.MkdirAll(usr.HomeDir+"/.somecontext", 0755)
	afero.WriteFile(fs, usr.HomeDir+"/.somecontext/somekeypair", []byte(validPrivateKey), 0644)

	key, err := pkp.LoadKey("somecontext", "somekeypair")
	assert.NoError(t, err)
	err = key.Validate()
	assert.NoError(t, err)
}

func TestLoadKeyFailsOnMissingFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	pkp := LocalFileSystemPKProvider{
		fileSystem: fs,
	}

	_, err := pkp.LoadKey("somecontext", "somekeypair")
	assert.Error(t, err)
}
