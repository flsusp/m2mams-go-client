package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	. "github.com/flsusp/m2mams-signer-go/m2mams"
	"github.com/urfave/cli/v2"
	"os"
	"os/user"
)

func main() {
	usr, err := user.Current()
	PanicOnError(err)

	app := &cli.App{
		Action: func(c *cli.Context) error {
			uid := c.Args().Get(0)
			if uid == "" {
				panic(fmt.Errorf("<uid> is required"))
			}

			context := Coalesce(c.Args().Get(1), "m2mams")
			keyPair := Coalesce(c.Args().Get(2), "id_rsa")

			dir := fmt.Sprintf("%s/.%s/%s", usr.HomeDir, context, uid)
			os.MkdirAll(dir, 0700)

			privateKeyFile := fmt.Sprintf("%s/%s", dir, keyPair)
			publicKeyFile := fmt.Sprintf("%s.pub.pem", privateKeyFile)

			reader := rand.Reader
			bitSize := 4096

			key, err := rsa.GenerateKey(reader, bitSize)
			PanicOnError(err)

			savePEMKey(privateKeyFile, key)
			savePublicPEMKey(publicKeyFile, key.PublicKey)

			protectFiles(privateKeyFile, publicKeyFile)

			return nil
		},
		Name:      "M2MAMS Generator",
		Usage:     "CLI that can be used to generate key pair for signing JWT tokens",
		Version:   "1.0.0",
		UsageText: "m2mams_generator <uid> <context> <key pair>",
		Description: "Generates a key pair that can be used to sign tokens using M2MAMS. The output for generating the " +
			"keys is given by the <context> and <key pair> parameters. With these parameters the files generated to" +
			"store the keys would be:\n\n" +
			"   `$HOME/.<context>/<uid>/<key pair>`: with the private key\n" +
			"   `$HOME/.<context>/<uid>/<key pair>.pub.pem`: with the public key in the PEM format\n\n" +
			"   These files are generated as described by https://github.com/flsusp/m2mams.\n\n" +
			"   The default values for <context> and <key pair> are `m2mams` and `id_rsa`, respectively. The value for " +
			"<uid> is used to identify the user at the verifier / server side and usually it is an email address.",
	}

	err = app.Run(os.Args)
	PanicOnError(err)
}

func protectFiles(privateKeyFile string, publicKeyFile string) {
	os.Chmod(privateKeyFile, 0400)
	os.Chmod(publicKeyFile, 0440)
}

func savePEMKey(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	PanicOnError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	PanicOnError(err)
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	PanicOnError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	PanicOnError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	PanicOnError(err)
}
