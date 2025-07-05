//go:debug rsa1024min=0
package crypt_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/crypt"
)

func TestRSASigning(t *testing.T) {
	rsaGenerator := crypt.RSAGenerator{}
	rsaKeyPair, err := rsaGenerator.Generate()
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	rsaSigner, err := crypt.NewRSAKeySigner(x509.MarshalPKCS1PrivateKey(rsaKeyPair.Private))
	if err != nil {
		t.Fatalf("Failed to create RSA signer: %v", err)
	}

	dataToBeSigned := []byte("test data")

	signature, err := rsaSigner.Sign(dataToBeSigned)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	hashed := sha256.Sum256(dataToBeSigned)
	err = rsa.VerifyPKCS1v15(rsaKeyPair.Public, crypto.SHA256, hashed[:], signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
}

func TestECCSigning(t *testing.T) {
	eccGenerator := crypt.ECCGenerator{}
	eccKeyPair, err := eccGenerator.Generate()
	if err != nil {
		t.Fatalf("Failed to generate ECC key pair: %v", err)
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(eccKeyPair.Private)
	if err != nil {
		t.Fatalf("Failed to marshal ECC private key: %v", err)
	}

	eccSigner, err := crypt.NewECCKeySigner(privateKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create ECC signer: %v", err)
	}

	dataToBeSigned := []byte("test data")

	signature, err := eccSigner.Sign(dataToBeSigned)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	hashed := sha256.Sum256(dataToBeSigned)
	valid := ecdsa.VerifyASN1(eccKeyPair.Public, hashed[:], signature)
	if !valid {
		t.Fatalf("Failed to verify signature")
	}
}

func TestDataFormatting(t *testing.T) {
	signatureCounter := 0
	dataToBeSigned := "test data"
	deviceID := "device123"
	lastSignature := base64.StdEncoding.EncodeToString([]byte(deviceID))

	securedDataToBeSigned := fmt.Sprintf("%d_%s_%s", signatureCounter, dataToBeSigned, lastSignature)

	expectedFormat := fmt.Sprintf("0_test data_%s", lastSignature)
	if securedDataToBeSigned != expectedFormat {
		t.Errorf("Expected formatted data to be %s, got %s", expectedFormat, securedDataToBeSigned)
	}
}
