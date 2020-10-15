package kprovider

import (
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/spf13/afero"
	"io/ioutil"
	"os/user"
	"strings"
)

type LocalFileSystemKProvider struct {
	FileSystem afero.Fs
}

func NewLocalFileSystemKProvider() KeyProvider {
	return LocalFileSystemKProvider{
		FileSystem: afero.NewOsFs(),
	}
}

func (w LocalFileSystemKProvider) LoadPrivateKey(context string, keyPair string) (*rsa.PrivateKey, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	privateKeyFilePath := fmt.Sprintf("%s/.%s/%s", usr.HomeDir, context, keyPair)

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

func (w LocalFileSystemKProvider) LoadKeyUid(context string, keyPair string) (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}

	publicKeyFilePath := fmt.Sprintf("%s/.%s/%s.pub", usr.HomeDir, context, keyPair)

	file, err := w.FileSystem.Open(publicKeyFilePath)
	if err != nil {
		return "", fmt.Errorf("unable to load public key from file %s: %s", publicKeyFilePath, err.Error())
	}
	defer file.Close()

	keyData, err := ioutil.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("unable to load public key from file %s: %s", publicKeyFilePath, err.Error())
	}

	keyFields := strings.Fields(string(keyData))
	return keyFields[len(keyFields)-1], nil
}
