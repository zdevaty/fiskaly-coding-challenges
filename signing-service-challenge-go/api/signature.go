package api

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/crypt"
	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/domain"
)

type signRequest struct {
	DataToBeSigned string `json:"data_to_be_signed"`
}

type signResponse struct {
	Signature  string `json:"signature"`
	SignedData string `json:"signed_data"`
}

func (s *Server) SignData(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	device, err := s.store.Get(id)
	if err != nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	var req signRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	counter := device.SignatureCounter
	lastSignature := getLastSignature(device)

	securedData := fmt.Sprintf("%d_%s_%s", counter, req.DataToBeSigned, lastSignature)

	signature, err := signData(securedData, device.Algorithm, device.PrivateKey)
	if err != nil {
		http.Error(w, "Signing failed", http.StatusInternalServerError)
		return
	}

	device.LastSignature = base64.StdEncoding.EncodeToString(signature)
	device.SignatureCounter += 1
	if err := s.store.Update(device); err != nil {
		http.Error(w, "Failed to update device", http.StatusInternalServerError)
		return
	}

	response := signResponse{
		Signature:  base64.StdEncoding.EncodeToString(signature),
		SignedData: securedData,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func getLastSignature(device domain.SignatureDevice) string {
	if device.LastSignature == "" {
		return base64.StdEncoding.EncodeToString([]byte(device.ID))
	}

	return device.LastSignature
}

func signData(data string, algorithm string, privateKey []byte) ([]byte, error) {
	var signer crypt.Signer
	var err error

	switch algorithm {
	case "ECC":
		signer, err = crypt.NewECCKeySigner(privateKey)
	case "RSA":
		signer, err = crypt.NewRSAKeySigner(privateKey)
	default:
		return nil, errors.New("unsupported algorithm")
	}
	if err != nil {
		return nil, err
	}

	return signer.Sign([]byte(data))
}

func signWithECC(data string, privateKey []byte) ([]byte, error) {
	privKey, err := x509.ParseECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256([]byte(data))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(ecdsaSignature{r, s})
}

func signWithRSA(data string, privateKey []byte) ([]byte, error) {
	privKey, err := x509.ParsePKCS1PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256([]byte(data))
	return rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
}

type ecdsaSignature struct {
	R, S *big.Int
}
