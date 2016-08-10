package services

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func VerifierFromString(publicKey string) (*Verifier, error) {
	return VerifierFromBytes([]byte(publicKey))
}

func VerifierFromBytes(publicKey []byte) (*Verifier, error) {
	return parsePublicKey(publicKey)
}

func parsePublicKey(bytes []byte) (*Verifier, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		key, err := ssh.ParsePublicKey(bytes)
		if err != nil {
			return nil, errors.New("no key found")
		}

		return &Verifier{&sshPublicKey{key}}, nil
	}

	var rawkey interface{}

	switch block.Type {
	case "PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		rawkey = rsa

	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}

	return newVerifierFromKey(rawkey)
}

func newVerifierFromKey(key interface{}) (*Verifier, error) {
	var verifier Verifier

	switch k := key.(type) {
	case *rsa.PublicKey:
		verifier = Verifier{&rsaPublicKey{k}}

	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}

	return &verifier, nil
}
