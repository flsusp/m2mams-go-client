package main

import (
	"fmt"
	. "github.com/flsusp/m2mams-signer-go/m2mams"
	"github.com/flsusp/m2mams-signer-go/m2mams/kprovider"
	"github.com/flsusp/m2mams-signer-go/m2mams/signer"
	"github.com/urfave/cli/v2"
	"os"
)

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
		Commands: []*cli.Command{
			{
				Name:    "add",
				Aliases: []string{"a"},
				Usage:   "add a task to the list",
				Action: func(c *cli.Context) error {
					fmt.Println("added task: ", c.Args().First())
					return nil
				},
			},
		},
		Action: func(c *cli.Context) error {
			uid := c.Args().Get(0)
			if uid == "" {
				panic(fmt.Errorf("<uid> is required"))
			}

			context := Coalesce(c.Args().Get(1), "m2mams")
			keyPair := Coalesce(c.Args().Get(2), "id_rsa")

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
				Uid:         uid,
				Context:     context,
				KeyPair:     keyPair,
			}

			tk, err := s.GenerateSignedToken()
			PanicOnError(err)

			fmt.Println(tk)

			return nil
		},
		Name:      "M2MAMS Signer",
		Usage:     "CLI that can be used to generate signed JWT tokens",
		Version:   "1.0.0",
		UsageText: "m2mams_signer [--kprovider file|env] <uid> <context> <key pair>",
		Description: "Generates a JWT signed token getting the keys from the given `--kprovider` and identifying the " +
			"key file or environment variable by the <uid>, <context> and <key pair> parameters.\n\n" +
			"   If the `--kprovider file` we expect to get the private key used for generating a signed token at" +
			"`$HOME/.<context>/<uid>/<key pair>`. This file can be generated as described by https://github.com/flsusp/m2mams.\n\n" +
			"   If the `--kprovider env` we expect to have an environment variables named `<context>_<key pair>_PK` " +
			"(all uppercase letters) with the private key to be used in the PEM format.",
	}

	err := app.Run(os.Args)
	PanicOnError(err)
}
