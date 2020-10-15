package kprovider

import (
	"crypto/rsa"
)

type KeyProvider interface {
	LoadPrivateKey(context string, keyPair string) (*rsa.PrivateKey, error)
	LoadKeyUid(context string, keyPair string) (string, error)
}
