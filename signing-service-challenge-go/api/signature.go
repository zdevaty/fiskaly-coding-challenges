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
	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/persistence"
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

	var signedData string
	var signature []byte
	var (
		ErrRequest  = errors.New("invalid request")
		ErrInternal = errors.New("internal error")
	)
	operation := func(device *domain.SignatureDevice) error {
		var req signRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return fmt.Errorf("invalid request body: %w", err)
		}
		defer r.Body.Close()

		if req.DataToBeSigned == "" {
			return fmt.Errorf("%w: data_to_be_signed is required", ErrRequest)
		}

		counter := device.SignatureCounter
		lastSignature := getLastSignature(*device)
		signedData = fmt.Sprintf("%d_%s_%s", counter, req.DataToBeSigned, lastSignature)

		var err error
		signature, err = signData(signedData, device.Algorithm, device.PrivateKey)
		if err != nil {
			return fmt.Errorf("%w: signing failed: %v", ErrInternal, err)
		}

		device.LastSignature = base64.StdEncoding.EncodeToString(signature)
		device.SignatureCounter += 1
		return nil
	}

	if err := s.store.InTx(id, operation); err != nil {
		var status int
		var msg string
		switch {
		case errors.Is(err, persistence.ErrDeviceNotFound):
			status, msg = http.StatusNotFound, err.Error()
		case errors.Is(err, ErrRequest):
			status, msg = http.StatusBadRequest, err.Error()
		case errors.Is(err, ErrInternal):
			status, msg = http.StatusInternalServerError, err.Error()
		default:
			status, msg = http.StatusInternalServerError, "Operation failed"
			log.Default().Printf("unexpected error: %v", err)
		}
		WriteErrorResponse(w, status, []string{msg})
		return
	}

	response := SignResponse{
		Signature:  base64.StdEncoding.EncodeToString(signature),
		SignedData: signedData,
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
