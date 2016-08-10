package services

import "golang.org/x/crypto/ssh"

type sshPublicKey struct {
	ssh.PublicKey
}

func (s *sshPublicKey) verify(bytes []byte, signature []byte) error {
	return s.Verify(bytes, &ssh.Signature{
		Format: "ssh-rsa",
		Blob:   signature,
	})
}
