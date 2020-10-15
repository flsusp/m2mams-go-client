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
		FileSystem: fs,
	}

	fs.MkdirAll(usr.HomeDir+"/.somecontext", 0755)
	afero.WriteFile(fs, usr.HomeDir+"/.somecontext/somekeypair", []byte(validPrivateKey), 0644)

	key, err := pkp.LoadPrivateKey("somecontext", "somekeypair")
	assert.NoError(t, err)
	err = key.Validate()
	assert.NoError(t, err)
}

func TestLoadKeyFailsOnMissingFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	pkp := LocalFileSystemPKProvider{
		FileSystem: fs,
	}

	_, err := pkp.LoadPrivateKey("somecontext", "somekeypair")
	assert.Error(t, err)
}

func TestLoadKeyUidFromFile(t *testing.T) {
	usr, err := user.Current()

	fs := afero.NewMemMapFs()
	pkp := LocalFileSystemPKProvider{
		FileSystem: fs,
	}

	fs.MkdirAll(usr.HomeDir+"/.somecontext", 0755)
	afero.WriteFile(fs, usr.HomeDir+"/.somecontext/somekeypair.pub", []byte(validPublicKey), 0644)

	uid, err := pkp.LoadKeyUid("somecontext", "somekeypair")
	assert.NoError(t, err)
	assert.Equal(t, "your_email@example.com", uid)
}
