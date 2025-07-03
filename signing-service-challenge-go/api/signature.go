package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/crypt"
	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/domain"
)

type signRequest struct {
	DataToBeSigned string `json:"data_to_be_signed"`
}

type SignResponse struct {
	Signature  string `json:"signature"`
	SignedData string `json:"signed_data"`
}

func (s *Server) SignData(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "device ID is required", http.StatusBadRequest)
		return
	}

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
	defer r.Body.Close()

	if req.DataToBeSigned == "" {
		http.Error(w, "data_to_be_signed is required", http.StatusBadRequest)
		return
	}

	counter := device.SignatureCounter
	lastSignature := getLastSignature(device)

	securedData := fmt.Sprintf("%d_%s_%s", counter, req.DataToBeSigned, lastSignature)

	signature, err := signData(securedData, device.Algorithm, device.PrivateKey)
	if err != nil {
		log.Default().Printf("signing data: %v", err)
		http.Error(w, "Signing failed", http.StatusInternalServerError)
		return
	}

	device.LastSignature = base64.StdEncoding.EncodeToString(signature)
	device.SignatureCounter += 1
	if err := s.store.Update(device); err != nil {
		http.Error(w, "Failed to update device", http.StatusInternalServerError)
		return
	}

	response := SignResponse{
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
