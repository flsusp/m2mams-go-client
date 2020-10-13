package m2mams

import (
	"crypto/rsa"
)

type PrivateKeyProvider interface {
	LoadKey(context string, keyPair string) (*rsa.PrivateKey, error)
}
