package services

import (
	"encoding/hex"
	"errors"
	"net/url"
	"time"
)

type Verifier struct {
	verifier
}

type verifier interface {
	verify(bytes []byte, signature []byte) error
}

func (v *Verifier) Verify(url *url.URL) (bool, error) {
	isExpired, err := verifyExpiration(url)
	if err != nil || isExpired {
		return false, err
	}

	signature, err := getSignature(url)
	if err != nil {
		return false, err
	}

	newURL := removeSignature(url)

	err = v.verify(newURL, signature)
	if err != nil {
		return false, err
	}

	return true, nil
}

func verifyExpiration(url *url.URL) (bool, error) {
	expireValue := url.Query().Get(urlExpire)
	if expireValue == "" {
		return true, errors.New("no expire parameter")
	}

	expire, err := time.Parse(timeFormat, expireValue)
	if err != nil {
		return true, err
	}

	return expire.Before(time.Now().UTC()), nil
}

func getSignature(url *url.URL) ([]byte, error) {
	signature := url.Query().Get(urlSignature)
	if signature == "" {
		return nil, errors.New("no signature parameter")
	}

	return hex.DecodeString(signature)
}

func removeSignature(url *url.URL) []byte {
	values := url.Query()
	values.Del(urlSignature)

	url.RawQuery = values.Encode()

	return []byte(url.String())
}
