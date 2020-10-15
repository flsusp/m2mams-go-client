package kprovider

import (
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/flsusp/m2mams-go-client/m2mams"
	"strings"
)

type EnvironmentVariablePKProvider struct {
	Environment m2mams.Environment
}

func (w EnvironmentVariablePKProvider) LoadPrivateKey(context string, keyPair string) (*rsa.PrivateKey, error) {
	genericVar := "M2MAMS-PK"
	specificContextKeyParVar := strings.ToUpper(fmt.Sprintf("%s-%s-PK", context, keyPair))

	key, err, done := w.loadKeyFromEnvVar(specificContextKeyParVar)
	if err != nil {
		return nil, err
	}
	if done {
		return key, nil
	}

	key, err, done = w.loadKeyFromEnvVar(genericVar)
	if err != nil {
		return nil, err
	}
	if done {
		return key, nil
	}

	return nil, fmt.Errorf("one of %s or %s environment variables should be defined", specificContextKeyParVar, genericVar)
}

func (w EnvironmentVariablePKProvider) LoadKeyUid(context string, keyPair string) (string, error) {
	genericVar := "M2MAMS-UID"
	specificContextKeyParVar := strings.ToUpper(fmt.Sprintf("%s-%s-UID", context, keyPair))

	uid := w.Environment.Getenv(specificContextKeyParVar)
	if uid != "" {
		return uid, nil
	}

	uid = w.Environment.Getenv(genericVar)
	if uid != "" {
		return uid, nil
	}

	return "", fmt.Errorf("one of %s or %s environment variables should be defined", specificContextKeyParVar, genericVar)
}

func (w EnvironmentVariablePKProvider) loadKeyFromEnvVar(envVarName string) (*rsa.PrivateKey, error, bool) {
	keyData := w.Environment.Getenv(envVarName)
	if keyData != "" {
		key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(keyData))
		if err != nil {
			return nil, fmt.Errorf("invalid PEM encoded private key on variable %s", envVarName), false
		}
		return key, nil, true
	}
	return nil, nil, false
}
