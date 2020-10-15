package m2mams_signer

import (
	"github.com/dgrijalva/jwt-go"
	m2mamspkp "github.com/flsusp/m2mams-go-client/m2mams/key_provider"
	"time"
)

type Signer struct {
	KeyProvider m2mamspkp.KeyProvider
	Context     string
	KeyPair     string
}

func (s Signer) GenerateSignedToken() (string, error) {
	key, err := s.KeyProvider.LoadPrivateKey(s.Context, s.KeyPair)
	if err != nil {
		return "", err
	}
	uid, err := s.KeyProvider.LoadKeyUid(s.Context, s.KeyPair)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"uid": uid,
		"kp":  s.KeyPair,
		"ts":  time.Now().Unix(),
	})
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
