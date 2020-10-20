package kprovider

import (
	"crypto/rsa"
)

type KeyProvider interface {
	LoadPrivateKey(uid string, context string, keyPair string) (*rsa.PrivateKey, error)
}
