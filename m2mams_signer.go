package main

import (
	"fmt"
	kprovider "github.com/flsusp/m2mams-go-client/m2mams/key_provider"
	signer "github.com/flsusp/m2mams-go-client/m2mams/signer"
	"github.com/urfave/cli/v2"
	"os"
)

var app = cli.NewApp()

func main() {
	var keyProvider string

	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "kprovider",
				Aliases:     []string{"kp"},
				Value:       "file",
				Usage:       "from where retrieve the signing keys (file | env)",
				Destination: &keyProvider,
			},
		},
		Action: func(c *cli.Context) error {
			context := coalesce(c.Args().Get(0), "m2mams")
			keyPair := coalesce(c.Args().Get(1), "id_rsa")

			var kp kprovider.KeyProvider
			if keyProvider == "file" {
				kp = kprovider.NewLocalFileSystemKProvider()
			} else if keyProvider == "env" {
				kp = kprovider.NewEnvironmentVariableKProvider()
			} else {
				return cli.Exit("Invalid --kprovider value", 1)
			}

			s := signer.Signer{
				KeyProvider: kp,
				Context:     context,
				KeyPair:     keyPair,
			}

			tk, err := s.GenerateSignedToken()
			panicOnError(err)

			fmt.Println(tk)

			return nil
		},
		Name:      "M2MAMS Signer",
		Usage:     "CLI that can be used to generate signed JWT tokens",
		Version:   "1.0.0",
		UsageText: "m2mams_signer [--kprovider file|env] <context> <key pair>",
		Description: "Generates a JWT signed token getting the keys from the given `--kprovider` and identifying the " +
			"key file or environment variable by the <context> and <key pair> parameters.\n\n" +
			"   If the `--kprovider file` we expect to have 3 files at `$HOME/.<context>/`: `<key pair>`, `<key pair>.pub`, " +
			"and `<key pair>.pub.pem`. These files can be generated as described by https://github.com/flsusp/m2mams.\n\n" +
			"   If the `--kprovider env` we expect to have 2 environment variables defined: `<context>_<key pair>_PK` " +
			"(all uppercase letters) with the private key to be used and `<context>_<key pair>_UID` with the user id " +
			"to be present as a claim in the JWT token.",
	}

	err := app.Run(os.Args)
	panicOnError(err)
}

func coalesce(first string, second string) string {
	if first != "" {
		return first
	}
	return second
}

func panicOnError(err error) {
	if err != nil {
		panic(err.Error())
	}
}
