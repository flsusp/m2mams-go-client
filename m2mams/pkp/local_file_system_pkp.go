package m2mams_pkp

import (
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/spf13/afero"
	"io/ioutil"
	"os/user"
)

type LocalFileSystemPKProvider struct {
	fileSystem afero.Fs
}

func NewLocalFileSystemPKProvider() LocalFileSystemPKProvider {
	return LocalFileSystemPKProvider{
		fileSystem: afero.NewOsFs(),
	}
}

func (w LocalFileSystemPKProvider) LoadKey(context string, keyPair string) (*rsa.PrivateKey, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	privateKeyFilePath := fmt.Sprintf("%s/.%s/%s", usr.HomeDir, context, keyPair)

	file, err := w.fileSystem.Open(privateKeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to load private key from file %s: %s", privateKeyFilePath, err.Error())
	}
	defer file.Close()

	keyData, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("unable to load private key from file %s: %s", privateKeyFilePath, err.Error())
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return nil, fmt.Errorf("invalid PEM encoded private key on file %s: %s", privateKeyFilePath, err.Error())
	}
	return key, nil
}
