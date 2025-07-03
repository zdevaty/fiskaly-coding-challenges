package crypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
)

// Signer defines a contract for different types of signing implementations.
type Signer interface {
	Sign(dataToBeSigned []byte) ([]byte, error)
}

// RSAKeySigner implements Signer for RSA keys
type RSAKeySigner struct {
	privateKey *rsa.PrivateKey
}

func NewRSAKeySigner(privateKeyBytes []byte) (*RSAKeySigner, error) {
	privKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	return &RSAKeySigner{privateKey: privKey}, nil
}

func (s *RSAKeySigner) Sign(dataToBeSigned []byte) ([]byte, error) {
	hashed := sha256.Sum256(dataToBeSigned)
	return rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hashed[:])
}

// ECCKeySigner implements Signer for ECC keys
type ECCKeySigner struct {
	privateKey *ecdsa.PrivateKey
}

func NewECCKeySigner(privateKeyBytes []byte) (*ECCKeySigner, error) {
	privKey, err := x509.ParseECPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	return &ECCKeySigner{privateKey: privKey}, nil
}

func (s *ECCKeySigner) Sign(dataToBeSigned []byte) ([]byte, error) {
	hashed := sha256.Sum256(dataToBeSigned)
	asn, err := ecdsa.SignASN1(rand.Reader, s.privateKey, hashed[:])
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn)
}
