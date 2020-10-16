package m2mams_signer

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	kprovider "github.com/flsusp/m2mams-signer-go/m2mams/key_provider"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"os/user"
	"testing"
)

var validPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n"
var validPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCyG3+ncO7fHc1W+gEjDPqNQn+RFnr35Ba1qovEtZoB/8EMfjP6fApM66RGeuHNLsWkPQQFdY5yelgMO+CbNaJrykGe1JWT8ZyLjZ0dUIOESAIIBZfYjxWXy909+QaEtk4n1SSzsMn251Gssj8fUcr6gApY1ga5ILeubT4xoKmbNNvJEmARApoLqf2vUcjnV0617hlLJ9ZJpz2gL3T11z+hkkpx7exYzbqIMGEsTaRNMGYMvIx2YGgTztnZzcC4L2Ad5ds3AA3oj2FE/jxT3EejAzK9Z6G8YfzBY4oJYX8LW9yiJIx32Fc7/uDdmoLMbM8cWYK1Bf757YzcXg8hHuPnlDScryR5dkrtPu8Hvgl7iBrVKNFeBrlWos+eBvf28y9pkNyptvUOb9Hly6RQKOPf4gsgDcw4QZnDt3LHyVQgig6BXBjcHZVLuNeeGqcDk1H6wIlBmHM2ofdvFt4a2w+6JzGTYsZShWK+eBHKOfhRXODQj4jGpQ2DRn8OQv9Rqw3I03xcA9NUOZfkTz2r4f6OLdvyV2nGyVNNZBTMOUJ7JR6r0fuuh8DJCj5LK5C9WuT1cfkq+sNWQ1ybMSdN1MhzHdGwgpdc1aiEmwsoqKwGbp3ZaYKkWA2wjKm8waKHdiS22VCku8elxGOXoqE6AY3G2TGdQ/9DalFvaPo0MXQU5Q== your_email@example.com"
var validPublicKeyPem = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsht/p3Du3x3NVvoBIwz6\njUJ/kRZ69+QWtaqLxLWaAf/BDH4z+nwKTOukRnrhzS7FpD0EBXWOcnpYDDvgmzWi\na8pBntSVk/Gci42dHVCDhEgCCAWX2I8Vl8vdPfkGhLZOJ9Uks7DJ9udRrLI/H1HK\n+oAKWNYGuSC3rm0+MaCpmzTbyRJgEQKaC6n9r1HI51dOte4ZSyfWSac9oC909dc/\noZJKce3sWM26iDBhLE2kTTBmDLyMdmBoE87Z2c3AuC9gHeXbNwAN6I9hRP48U9xH\nowMyvWehvGH8wWOKCWF/C1vcoiSMd9hXO/7g3ZqCzGzPHFmCtQX++e2M3F4PIR7j\n55Q0nK8keXZK7T7vB74Je4ga1SjRXga5VqLPngb39vMvaZDcqbb1Dm/R5cukUCjj\n3+ILIA3MOEGZw7dyx8lUIIoOgVwY3B2VS7jXnhqnA5NR+sCJQZhzNqH3bxbeGtsP\nuicxk2LGUoVivngRyjn4UVzg0I+IxqUNg0Z/DkL/UasNyNN8XAPTVDmX5E89q+H+\nji3b8ldpxslTTWQUzDlCeyUeq9H7rofAyQo+SyuQvVrk9XH5KvrDVkNcmzEnTdTI\ncx3RsIKXXNWohJsLKKisBm6d2WmCpFgNsIypvMGih3YkttlQpLvHpcRjl6KhOgGN\nxtkxnUP/Q2pRb2j6NDF0FOUCAwEAAQ==\n-----END PUBLIC KEY-----\n"

func TestGenerateSignedToken(t *testing.T) {
	usr, _ := user.Current()

	fs := afero.NewMemMapFs()
	pkp := kprovider.LocalFileSystemKProvider{
		FileSystem: fs,
	}

	fs.MkdirAll(usr.HomeDir+"/.somecontext", 0755)
	afero.WriteFile(fs, usr.HomeDir+"/.somecontext/somekeypair", []byte(validPrivateKey), 0644)
	afero.WriteFile(fs, usr.HomeDir+"/.somecontext/somekeypair.pub", []byte(validPublicKey), 0644)
	afero.WriteFile(fs, usr.HomeDir+"/.somecontext/somekeypair.pub.pem", []byte(validPublicKeyPem), 0644)

	signer := Signer{
		KeyProvider: pkp,
		Context:     "somecontext",
		KeyPair:     "somekeypair",
	}

	token, err := signer.GenerateSignedToken()
	assert.NoError(t, err)

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return jwt.ParseRSAPublicKeyFromPEM([]byte(validPublicKeyPem))
	})
	assert.NoError(t, err)
	assert.True(t, parsedToken.Valid)

	claims := parsedToken.Claims.(jwt.MapClaims)
	assert.Equal(t, "your_email@example.com", claims["uid"])
	assert.Equal(t, "somekeypair", claims["kp"])
}
