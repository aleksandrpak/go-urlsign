package services

import (
	"encoding/hex"
	"net/url"
	"time"
)

type Signer struct {
	signer
}

type signer interface {
	sign(bytes []byte) ([]byte, error)
}

func (s *Signer) Sign(url *url.URL, expireAfter time.Duration) error {
	addExpiration(url, expireAfter)

	signature, err := s.sign([]byte(url.String()))
	if err != nil {
		return err
	}

	addSignature(url, signature)
	return nil
}

func addExpiration(url *url.URL, expireAfter time.Duration) {
	expire := time.Now().UTC().Add(expireAfter)

	values := url.Query()
	values.Add(urlExpire, expire.Format(timeFormat))

	url.RawQuery = values.Encode()
}

func addSignature(url *url.URL, signature []byte) {
	values := url.Query()
	values.Add(urlSignature, hex.EncodeToString(signature))

	url.RawQuery = values.Encode()
}
