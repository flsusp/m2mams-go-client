package kprovider

import (
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/spf13/afero"
	"io/ioutil"
	"os/user"
)

type LocalFileSystemKProvider struct {
	FileSystem afero.Fs
}

func NewLocalFileSystemKProvider() KeyProvider {
	return LocalFileSystemKProvider{
		FileSystem: afero.NewOsFs(),
	}
}

func (w LocalFileSystemKProvider) LoadPrivateKey(uid string, context string, keyPair string) (*rsa.PrivateKey, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	privateKeyFilePath := fmt.Sprintf("%s/.%s/%s/%s", usr.HomeDir, context, uid, keyPair)

	file, err := w.FileSystem.Open(privateKeyFilePath)
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
