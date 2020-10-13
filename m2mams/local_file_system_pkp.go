package m2mams

import (
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"os/user"
)

type LocalFileSystemPKProvider struct {
}

func (w LocalFileSystemPKProvider) LoadKey(context string, keyPair string) (*rsa.PrivateKey, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	privateKeyFilePath := fmt.Sprintf("%s/.%s/%s", usr.HomeDir, context, keyPair)
	keyData, err := ioutil.ReadFile(privateKeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to load private key from file %s: %s", privateKeyFilePath, err.Error())
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return nil, fmt.Errorf("invalid PEM encoded private key on file %s: %s", privateKeyFilePath, err.Error())
	}
	return key, nil
}

