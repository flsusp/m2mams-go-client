package m2mams_pkp

import (
	"crypto/rsa"
)

type PrivateKeyProvider interface {
	LoadKey(context string, keyPair string) (*rsa.PrivateKey, error)
}
