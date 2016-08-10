package services

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

type rsaPrivateKey struct {
	*rsa.PrivateKey
}

func (r *rsaPrivateKey) sign(bytes []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(bytes)

	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, h.Sum(nil))
}
