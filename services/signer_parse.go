package services

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func SignerFromString(privateKey string) (*Signer, error) {
	return SignerFromBytes([]byte(privateKey))
}

func SignerFromBytes(privateKey []byte) (*Signer, error) {
	return parsePrivateKey(privateKey)
}

func parsePrivateKey(pemBytes []byte) (*Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa

	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}

	return newSignerFromKey(rawkey)
}

func newSignerFromKey(key interface{}) (*Signer, error) {
	var signer Signer

	switch k := key.(type) {
	case *rsa.PrivateKey:
		signer = Signer{&rsaPrivateKey{k}}

	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}

	return &signer, nil
}
