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
		WriteErrorResponse(w, http.StatusBadRequest, []string{"device ID is required"})
		return
	}

	device, err := s.store.Get(id)
	if err != nil {
		WriteErrorResponse(w, http.StatusNotFound, []string{"Device not found"})
		return
	}

	var req signRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, []string{"Invalid request body"})
		return
	}
	defer r.Body.Close()

	if req.DataToBeSigned == "" {
		WriteErrorResponse(w, http.StatusBadRequest, []string{"data_to_be_signed is required"})
		return
	}

	counter := device.SignatureCounter
	lastSignature := getLastSignature(device)
	securedData := fmt.Sprintf("%d_%s_%s", counter, req.DataToBeSigned, lastSignature)

	signature, err := signData(securedData, device.Algorithm, device.PrivateKey)
	if err != nil {
		log.Default().Printf("signing data: %v", err)
		WriteErrorResponse(w, http.StatusInternalServerError, []string{"Signing failed"})
		return
	}

	device.LastSignature = base64.StdEncoding.EncodeToString(signature)
	device.SignatureCounter += 1

	if err := s.store.Update(device); err != nil {
		WriteErrorResponse(w, http.StatusInternalServerError, []string{"Failed to update device"})
		return
	}

	response := SignResponse{
		Signature:  base64.StdEncoding.EncodeToString(signature),
		SignedData: securedData,
	}
	WriteAPIResponse(w, http.StatusOK, response)
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
	case domain.AlgorithmECC:
		signer, err = crypt.NewECCKeySigner(privateKey)
	case domain.AlgorithmRSA:
		signer, err = crypt.NewRSAKeySigner(privateKey)
	default:
		return nil, errors.New("unsupported algorithm")
	}
	if err != nil {
		return nil, err
	}

	return signer.Sign([]byte(data))
}
