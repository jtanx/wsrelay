package main

import (
	"fmt"
	"io/ioutil"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func main() {
	opts := totp.GenerateOpts{
		Issuer:      "WSRelay",
		AccountName: "WSRelay",
		Algorithm:   otp.AlgorithmSHA512,
	}
	srvKey, err := totp.Generate(opts)
	if err != nil {
		panic(err)
	}
	cliKey, err := totp.Generate(opts)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("gen_defs.go", []byte(fmt.Sprintf(`package common

const (
	SrvKey = "%s"
	CliKey = "%s"
)
`, srvKey.Secret(), cliKey.Secret())), 0666)

	if err != nil {
		panic(err)
	}
}
