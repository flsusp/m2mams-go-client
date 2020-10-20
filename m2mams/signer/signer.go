package signer

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/flsusp/m2mams-signer-go/m2mams/kprovider"
	"time"
)

type Signer struct {
	KeyProvider kprovider.KeyProvider
	Uid         string
	Context     string
	KeyPair     string
}

func (s Signer) GenerateSignedToken() (string, error) {
	key, err := s.KeyProvider.LoadPrivateKey(s.Uid, s.Context, s.KeyPair)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"uid": s.Uid,
		"kp":  s.KeyPair,
		"ts":  time.Now().Unix(),
	})
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
