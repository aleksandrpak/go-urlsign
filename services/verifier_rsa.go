package services

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
)

type rsaPublicKey struct {
	*rsa.PublicKey
}

func (r *rsaPublicKey) verify(bytes []byte, signature []byte) error {
	h := sha256.New()
	h.Write(bytes)

	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, h.Sum(nil), signature)
}
